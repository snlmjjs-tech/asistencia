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

-- Permisos de tabla para el rol anon (sin esto aparece "permission denied for table docs").
grant usage on schema public to anon, authenticated;
grant select, insert, update, delete on public.docs to anon, authenticated;

-- ===== Clave compartida de acceso (validada en el servidor) =====
-- Reemplace CAMBIE_ESTA_CLAVE por la clave real ANTES de ejecutar, y no la guarde en el repositorio.
create or replace function public.clave_ok() returns boolean
language sql stable as $$
  select coalesce(current_setting('request.headers', true)::json ->> 'x-clave', '') = 'CAMBIE_ESTA_CLAVE'
$$;

create or replace function public.clave_valida() returns boolean
language sql stable as $$ select public.clave_ok() $$;
grant execute on function public.clave_ok(), public.clave_valida() to anon, authenticated;

drop policy if exists "docs_anon_all" on public.docs;
drop policy if exists "docs_clave" on public.docs;
create policy "docs_clave" on public.docs
  for all to anon, authenticated using (public.clave_ok()) with check (public.clave_ok());
