-- ============================================================
-- GAMIK — Dziennik elektroniczny
-- Schemat bazy danych dla Supabase (PostgreSQL) — wersja 2
-- ------------------------------------------------------------
-- Ten plik jest IDEMPOTENTNY: możesz go uruchomić na świeżej
-- bazie ORAZ ponownie na istniejącej (aktualizacja) — nie
-- usuwa danych. Uruchom całość w Supabase -> SQL Editor.
--
-- Pierwsze zarejestrowane konto = administrator (approved).
-- Kolejne konta = pending (czekają na akceptację admina).
--
-- Wersja 2 dodaje:
--  * przypisania nauczyciel–przedmiot–uczeń,
--  * zadania domowe + przesyłanie prac przez ucznia (pliki),
--  * sprawdziany (link lub plik),
--  * notatki (plik/treść od nauczyciela),
--  * magazyn plików (Supabase Storage, bucket "dziennik").
-- ============================================================

-- --- Typy wyliczeniowe -------------------------------------
do $$ begin create type user_role as enum ('admin','teacher','student');
exception when duplicate_object then null; end $$;
do $$ begin create type account_status as enum ('pending','approved','rejected');
exception when duplicate_object then null; end $$;
do $$ begin create type grade_category as enum ('regular','predicted','final');
exception when duplicate_object then null; end $$;

-- --- Tabele podstawowe -------------------------------------
create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  full_name text not null default '',
  email text,
  role user_role not null default 'student',
  status account_status not null default 'pending',
  created_at timestamptz not null default now()
);

create table if not exists public.subjects (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  created_at timestamptz not null default now()
);

create table if not exists public.grades (
  id uuid primary key default gen_random_uuid(),
  student_id uuid not null references public.profiles(id) on delete cascade,
  subject_id uuid not null references public.subjects(id) on delete cascade,
  teacher_id uuid references public.profiles(id) on delete set null,
  value text not null,
  weight int not null default 1,
  category grade_category not null default 'regular',
  description text,
  graded_on date not null default current_date,
  created_at timestamptz not null default now()
);

create table if not exists public.lessons (
  id uuid primary key default gen_random_uuid(),
  student_id uuid not null references public.profiles(id) on delete cascade,
  subject_id uuid not null references public.subjects(id) on delete cascade,
  teacher_id uuid references public.profiles(id) on delete set null,
  day_of_week int not null,
  start_time time not null,
  end_time time not null,
  meeting_url text,
  created_at timestamptz not null default now()
);

create table if not exists public.announcements (
  id uuid primary key default gen_random_uuid(),
  author_id uuid references public.profiles(id) on delete set null,
  title text not null,
  content text not null,
  created_at timestamptz not null default now()
);

-- --- NOWE: przypisania nauczyciel–przedmiot–uczeń ----------
create table if not exists public.teaching_assignments (
  id uuid primary key default gen_random_uuid(),
  teacher_id uuid not null references public.profiles(id) on delete cascade,
  subject_id uuid not null references public.subjects(id) on delete cascade,
  student_id uuid not null references public.profiles(id) on delete cascade,
  created_at timestamptz not null default now(),
  unique (teacher_id, subject_id, student_id)
);

-- --- NOWE: zadania domowe ----------------------------------
create table if not exists public.homework (
  id uuid primary key default gen_random_uuid(),
  student_id uuid not null references public.profiles(id) on delete cascade,
  subject_id uuid not null references public.subjects(id) on delete cascade,
  teacher_id uuid references public.profiles(id) on delete set null,
  title text not null,
  description text,
  due_date date,
  attachment_path text,          -- opcjonalny plik od nauczyciela (np. karta pracy)
  attachment_name text,
  created_at timestamptz not null default now()
);

-- prace przesłane przez ucznia
create table if not exists public.homework_submissions (
  id uuid primary key default gen_random_uuid(),
  homework_id uuid not null references public.homework(id) on delete cascade,
  student_id uuid not null references public.profiles(id) on delete cascade,
  file_path text not null,
  file_name text,
  note text,
  submitted_at timestamptz not null default now()
);

-- --- NOWE: sprawdziany -------------------------------------
create table if not exists public.tests (
  id uuid primary key default gen_random_uuid(),
  student_id uuid not null references public.profiles(id) on delete cascade,
  subject_id uuid not null references public.subjects(id) on delete cascade,
  teacher_id uuid references public.profiles(id) on delete set null,
  title text not null,
  description text,
  test_date date,
  link text,                     -- opcjonalny link do sprawdzianu
  attachment_path text,          -- lub plik ze sprawdzianem
  attachment_name text,
  created_at timestamptz not null default now()
);

-- --- NOWE: notatki -----------------------------------------
create table if not exists public.notes (
  id uuid primary key default gen_random_uuid(),
  student_id uuid not null references public.profiles(id) on delete cascade,
  subject_id uuid not null references public.subjects(id) on delete cascade,
  teacher_id uuid references public.profiles(id) on delete set null,
  title text not null,
  content text,
  attachment_path text,          -- plik z notatką
  attachment_name text,
  created_at timestamptz not null default now()
);

-- ============================================================
-- Funkcje pomocnicze (SECURITY DEFINER — omijają RLS)
-- ============================================================
create or replace function public.is_approved()
returns boolean language sql security definer stable set search_path=public as $$
  select exists(select 1 from public.profiles where id=auth.uid() and status='approved');
$$;

create or replace function public.is_admin()
returns boolean language sql security definer stable set search_path=public as $$
  select exists(select 1 from public.profiles where id=auth.uid() and role='admin' and status='approved');
$$;

create or replace function public.is_teacher()
returns boolean language sql security definer stable set search_path=public as $$
  select exists(select 1 from public.profiles where id=auth.uid() and role='teacher' and status='approved');
$$;

-- Czy bieżący użytkownik może działać na parze (uczeń, przedmiot)?
-- Administrator: zawsze. Nauczyciel: tylko jeśli ma przypisanie.
create or replace function public.teaches(p_student uuid, p_subject uuid)
returns boolean language sql security definer stable set search_path=public as $$
  select public.is_admin() or exists(
    select 1 from public.teaching_assignments
    where teacher_id=auth.uid() and student_id=p_student and subject_id=p_subject
  );
$$;

-- ============================================================
-- Trigger: nowy użytkownik -> profil (pierwszy = admin)
-- ============================================================
create or replace function public.handle_new_user()
returns trigger language plpgsql security definer set search_path=public as $$
declare user_count int; desired user_role;
begin
  select count(*) into user_count from public.profiles;
  if user_count=0 then
    insert into public.profiles(id,full_name,email,role,status)
    values(new.id,coalesce(new.raw_user_meta_data->>'full_name',''),new.email,'admin','approved');
  else
    begin desired := coalesce((new.raw_user_meta_data->>'role')::user_role,'student');
    exception when others then desired := 'student'; end;
    if desired='admin' then desired := 'student'; end if;
    insert into public.profiles(id,full_name,email,role,status)
    values(new.id,coalesce(new.raw_user_meta_data->>'full_name',''),new.email,desired,'pending');
  end if;
  return new;
end $$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created after insert on auth.users
  for each row execute function public.handle_new_user();

-- Ochrona: zwykły użytkownik nie zmieni sobie roli/statusu
create or replace function public.protect_profile_fields()
returns trigger language plpgsql security definer set search_path=public as $$
begin
  if not public.is_admin() then new.role := old.role; new.status := old.status; end if;
  return new;
end $$;
drop trigger if exists protect_profile on public.profiles;
create trigger protect_profile before update on public.profiles
  for each row execute function public.protect_profile_fields();

-- ============================================================
-- Row Level Security
-- ============================================================
alter table public.profiles             enable row level security;
alter table public.subjects             enable row level security;
alter table public.grades               enable row level security;
alter table public.lessons              enable row level security;
alter table public.announcements        enable row level security;
alter table public.teaching_assignments enable row level security;
alter table public.homework             enable row level security;
alter table public.homework_submissions enable row level security;
alter table public.tests                enable row level security;
alter table public.notes                enable row level security;

-- --- profiles ----------------------------------------------
drop policy if exists profiles_select on public.profiles;
create policy profiles_select on public.profiles for select
  using (id=auth.uid() or public.is_admin() or public.is_teacher());
drop policy if exists profiles_update on public.profiles;
create policy profiles_update on public.profiles for update
  using (id=auth.uid() or public.is_admin()) with check (id=auth.uid() or public.is_admin());
drop policy if exists profiles_delete on public.profiles;
create policy profiles_delete on public.profiles for delete using (public.is_admin());

-- --- subjects ----------------------------------------------
drop policy if exists subjects_select on public.subjects;
create policy subjects_select on public.subjects for select using (public.is_approved());
drop policy if exists subjects_insert on public.subjects;
create policy subjects_insert on public.subjects for insert with check (public.is_admin() or public.is_teacher());
drop policy if exists subjects_update on public.subjects;
create policy subjects_update on public.subjects for update using (public.is_admin() or public.is_teacher());
drop policy if exists subjects_delete on public.subjects;
create policy subjects_delete on public.subjects for delete using (public.is_admin() or public.is_teacher());

-- --- grades (teraz z uwzględnieniem przypisań) -------------
drop policy if exists grades_select on public.grades;
create policy grades_select on public.grades for select
  using (student_id=auth.uid() or public.teaches(student_id,subject_id));
drop policy if exists grades_insert on public.grades;
create policy grades_insert on public.grades for insert with check (public.teaches(student_id,subject_id));
drop policy if exists grades_update on public.grades;
create policy grades_update on public.grades for update using (public.teaches(student_id,subject_id));
drop policy if exists grades_delete on public.grades;
create policy grades_delete on public.grades for delete using (public.teaches(student_id,subject_id));

-- --- lessons -----------------------------------------------
drop policy if exists lessons_select on public.lessons;
create policy lessons_select on public.lessons for select
  using (student_id=auth.uid() or public.teaches(student_id,subject_id));
drop policy if exists lessons_insert on public.lessons;
create policy lessons_insert on public.lessons for insert with check (public.teaches(student_id,subject_id));
drop policy if exists lessons_update on public.lessons;
create policy lessons_update on public.lessons for update using (public.teaches(student_id,subject_id));
drop policy if exists lessons_delete on public.lessons;
create policy lessons_delete on public.lessons for delete using (public.teaches(student_id,subject_id));

-- --- announcements -----------------------------------------
drop policy if exists announcements_select on public.announcements;
create policy announcements_select on public.announcements for select using (public.is_approved());
drop policy if exists announcements_insert on public.announcements;
create policy announcements_insert on public.announcements for insert with check (public.is_admin());
drop policy if exists announcements_update on public.announcements;
create policy announcements_update on public.announcements for update using (public.is_admin());
drop policy if exists announcements_delete on public.announcements;
create policy announcements_delete on public.announcements for delete using (public.is_admin());

-- --- teaching_assignments ----------------------------------
drop policy if exists ta_select on public.teaching_assignments;
create policy ta_select on public.teaching_assignments for select
  using (public.is_admin() or teacher_id=auth.uid() or student_id=auth.uid());
drop policy if exists ta_insert on public.teaching_assignments;
create policy ta_insert on public.teaching_assignments for insert with check (public.is_admin());
drop policy if exists ta_update on public.teaching_assignments;
create policy ta_update on public.teaching_assignments for update using (public.is_admin());
drop policy if exists ta_delete on public.teaching_assignments;
create policy ta_delete on public.teaching_assignments for delete using (public.is_admin());

-- --- homework ----------------------------------------------
drop policy if exists hw_select on public.homework;
create policy hw_select on public.homework for select
  using (student_id=auth.uid() or public.teaches(student_id,subject_id));
drop policy if exists hw_insert on public.homework;
create policy hw_insert on public.homework for insert with check (public.teaches(student_id,subject_id));
drop policy if exists hw_update on public.homework;
create policy hw_update on public.homework for update using (public.teaches(student_id,subject_id));
drop policy if exists hw_delete on public.homework;
create policy hw_delete on public.homework for delete using (public.teaches(student_id,subject_id));

-- --- homework_submissions ----------------------------------
drop policy if exists hws_select on public.homework_submissions;
create policy hws_select on public.homework_submissions for select using (
  student_id=auth.uid() or exists(
    select 1 from public.homework h where h.id=homework_id and public.teaches(h.student_id,h.subject_id)
  )
);
drop policy if exists hws_insert on public.homework_submissions;
create policy hws_insert on public.homework_submissions for insert with check (
  student_id=auth.uid() and exists(
    select 1 from public.homework h where h.id=homework_id and h.student_id=auth.uid()
  )
);
drop policy if exists hws_delete on public.homework_submissions;
create policy hws_delete on public.homework_submissions for delete using (
  student_id=auth.uid() or public.is_admin()
);

-- --- tests -------------------------------------------------
drop policy if exists tests_select on public.tests;
create policy tests_select on public.tests for select
  using (student_id=auth.uid() or public.teaches(student_id,subject_id));
drop policy if exists tests_insert on public.tests;
create policy tests_insert on public.tests for insert with check (public.teaches(student_id,subject_id));
drop policy if exists tests_update on public.tests;
create policy tests_update on public.tests for update using (public.teaches(student_id,subject_id));
drop policy if exists tests_delete on public.tests;
create policy tests_delete on public.tests for delete using (public.teaches(student_id,subject_id));

-- --- notes -------------------------------------------------
drop policy if exists notes_select on public.notes;
create policy notes_select on public.notes for select
  using (student_id=auth.uid() or public.teaches(student_id,subject_id));
drop policy if exists notes_insert on public.notes;
create policy notes_insert on public.notes for insert with check (public.teaches(student_id,subject_id));
drop policy if exists notes_update on public.notes;
create policy notes_update on public.notes for update using (public.teaches(student_id,subject_id));
drop policy if exists notes_delete on public.notes;
create policy notes_delete on public.notes for delete using (public.teaches(student_id,subject_id));

-- ============================================================
-- STORAGE — bucket na pliki (zadania, prace, sprawdziany, notatki)
-- ============================================================
insert into storage.buckets (id, name, public)
values ('dziennik','dziennik', false)
on conflict (id) do nothing;

-- Odczyt (potrzebny do generowania podpisanych linków): każdy zatwierdzony użytkownik.
drop policy if exists dziennik_select on storage.objects;
create policy dziennik_select on storage.objects for select
  using (bucket_id='dziennik' and public.is_approved());

-- Wgrywanie: każdy zatwierdzony użytkownik (uczeń przesyła prace,
-- nauczyciel/admin wgrywa materiały). Nazwy plików są losowe (UUID).
drop policy if exists dziennik_insert on storage.objects;
create policy dziennik_insert on storage.objects for insert
  with check (bucket_id='dziennik' and public.is_approved());

drop policy if exists dziennik_update on storage.objects;
create policy dziennik_update on storage.objects for update
  using (bucket_id='dziennik' and public.is_approved());

-- Kasowanie: właściciel pliku, nauczyciel lub administrator.
drop policy if exists dziennik_delete on storage.objects;
create policy dziennik_delete on storage.objects for delete
  using (bucket_id='dziennik' and (public.is_admin() or public.is_teacher() or owner=auth.uid()));

-- ============================================================
-- Gotowe.
-- ============================================================

-- ============================================================
-- AKTUALIZACJA v3: typy ocen cząstkowych + wagi dziesiętne
-- (bezpieczne do ponownego uruchomienia)
-- ------------------------------------------------------------
--  kind        : 'numeric' (zwykła cyfrowa) | 'percent' | 'other'
--  subcategory : sprawdzian | kartkowka | egzamin | wypracowanie |
--                ustna | praca_domowa | aktywnosc | karta_pracy
--  weight      : liczba (0–1), egzamin = 1.5; procentowa/inna = 0
-- ============================================================
alter table public.grades add column if not exists kind text;
alter table public.grades add column if not exists subcategory text;
alter table public.grades alter column weight type numeric using weight::numeric;
alter table public.grades alter column weight set default 1;
