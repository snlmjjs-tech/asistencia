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

-- ===== Accesos: una clave por persona (validadas en el servidor) =====
-- Antes de ejecutar, reemplace CAMBIE_ESTA_CLAVE por la clave del primer administrador.
-- No guarde la clave real en el repositorio.
create table if not exists public.accesos (
  id     uuid primary key default gen_random_uuid(),
  clave  text not null unique,
  nombre text not null,
  rol    text not null default 'usuario' check (rol in ('admin','usuario')),
  activo boolean not null default true,
  creado timestamptz not null default now()
);
alter table public.accesos enable row level security;   -- sin políticas: nadie la lee directo
revoke all on public.accesos from anon, authenticated;

create or replace function public._clave() returns text
language sql stable as $$
  select coalesce((nullif(current_setting('request.headers', true), '')::json) ->> 'x-clave', '')
$$;

create or replace function public.clave_rol() returns text
language sql stable security definer set search_path = public as $$
  select rol from public.accesos where lower(clave) = lower(public._clave()) and activo limit 1
$$;

create or replace function public.clave_ok() returns boolean
language sql stable security definer set search_path = public as $$ select public.clave_rol() is not null $$;

create or replace function public.clave_valida() returns boolean
language sql stable security definer set search_path = public as $$ select public.clave_rol() is not null $$;

create or replace function public.mi_acceso() returns json
language sql stable security definer set search_path = public as $$
  select json_build_object('id', left(id::text, 8), 'nombre', nombre, 'rol', rol)
  from public.accesos where lower(clave) = lower(public._clave()) and activo limit 1
$$;

create or replace function public.accesos_nombres() returns table(id text, nombre text)
language sql stable security definer set search_path = public as $$
  select left(a.id::text, 8), a.nombre from public.accesos a where public.clave_rol() is not null
$$;

create or replace function public.accesos_listar() returns table(id uuid, nombre text, rol text, clave text, activo boolean, creado timestamptz)
language sql stable security definer set search_path = public as $$
  select a.id, a.nombre, a.rol, a.clave, a.activo, a.creado from public.accesos a
  where public.clave_rol() = 'admin' order by a.creado
$$;

create or replace function public.acceso_crear(p_nombre text, p_rol text default 'usuario') returns text
language plpgsql security definer set search_path = public as $$
declare h text; k text;
begin
  if public.clave_rol() is distinct from 'admin' then raise exception 'Solo un administrador puede crear claves'; end if;
  if coalesce(trim(p_nombre), '') = '' then raise exception 'Falta el nombre'; end if;
  if p_rol not in ('admin','usuario') then raise exception 'Tipo de acceso no válido'; end if;
  h := upper(replace(gen_random_uuid()::text, '-', ''));
  k := substr(h,1,4) || '-' || substr(h,5,4) || '-' || substr(h,9,4);
  insert into public.accesos(clave, nombre, rol) values (k, trim(p_nombre), p_rol);
  return k;
end $$;

create or replace function public.acceso_estado(p_id uuid, p_activo boolean) returns void
language plpgsql security definer set search_path = public as $$
begin
  if public.clave_rol() is distinct from 'admin' then raise exception 'Solo un administrador puede cambiar claves'; end if;
  if exists (select 1 from public.accesos where id = p_id and lower(clave) = lower(public._clave())) then
    raise exception 'No puede desactivar su propia clave';
  end if;
  update public.accesos set activo = p_activo where id = p_id;
end $$;

create or replace function public.acceso_eliminar(p_id uuid) returns void
language plpgsql security definer set search_path = public as $$
begin
  if public.clave_rol() is distinct from 'admin' then raise exception 'Solo un administrador puede eliminar claves'; end if;
  if exists (select 1 from public.accesos where id = p_id and lower(clave) = lower(public._clave())) then
    raise exception 'No puede eliminar su propia clave';
  end if;
  delete from public.accesos where id = p_id;
end $$;

grant execute on function public.clave_rol(), public.clave_ok(), public.clave_valida(), public.mi_acceso(),
  public.accesos_nombres(), public.accesos_listar(), public.acceso_crear(text, text),
  public.acceso_estado(uuid, boolean), public.acceso_eliminar(uuid) to anon, authenticated;

-- Primer administrador (cambie el nombre si quiere).
insert into public.accesos(clave, nombre, rol) values ('CAMBIE_ESTA_CLAVE', 'Administrador', 'admin')
on conflict (clave) do nothing;

drop policy if exists "docs_anon_all" on public.docs;
drop policy if exists "docs_clave" on public.docs;
create policy "docs_clave" on public.docs
  for all to anon, authenticated using (public.clave_ok()) with check (public.clave_ok());
