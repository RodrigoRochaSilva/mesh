-- Auth hardening for profiles access checks
-- Run in Supabase SQL editor

-- 1) Optional unique index for normalized email lookup
create unique index if not exists profiles_email_unique_idx
on public.profiles (lower(email));

-- 2) Index for user_type access checks (login gate)
create index if not exists profiles_user_type_idx
on public.profiles (user_type);

-- 3) Minimal RLS policy for direct self-read (if frontend ever queries profiles)
alter table public.profiles enable row level security;

do $$
begin
  if not exists (
    select 1
    from pg_policies
    where schemaname = 'public'
      and tablename = 'profiles'
      and policyname = 'profiles_select_own'
  ) then
    create policy profiles_select_own
      on public.profiles
      for select
      using (id = auth.uid());
  end if;
end $$;
