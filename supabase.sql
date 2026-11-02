-- Ejecutar una vez en Supabase > SQL Editor.
create table if not exists public.docs (
  coll       text not null,
  id         text not null,
  data       jsonb not null default '{}'::jsonb,
  updated_at timestamptz not null default now(),
  primary key (coll, id)
);
create index if not exists docs_data_gin on public.docs using gin (data);

alter table public.docs enable row level security;

-- Sin login: cualquiera con el enlace de la página puede leer y escribir (rol anon).
drop policy if exists "docs_anon_all" on public.docs;
create policy "docs_anon_all" on public.docs
  for all to anon, authenticated using (true) with check (true);

-- Actualización en vivo entre usuarios.
alter publication supabase_realtime add table public.docs;
