-- Permisos por funcionario: Administrador, Editor y Solo lectura, con cargo y clave a medida.
-- Ejecutar DESPUÉS de supabase.sql. Se puede repetir sin problema.

-- 1) Cargo y nuevos tipos de permiso
alter table public.accesos add column if not exists cargo text not null default '';
alter table public.accesos drop constraint if exists accesos_rol_check;
update public.accesos set rol = 'editor' where rol = 'usuario';
alter table public.accesos add constraint accesos_rol_check check (rol in ('admin','editor','lectura'));
alter table public.accesos alter column rol set default 'editor';

-- 2) Funciones
create or replace function public.clave_escribe() returns boolean
language sql stable security definer set search_path = public as $$
  select coalesce(public.clave_rol() in ('admin','editor'), false)
$$;

drop function if exists public.accesos_listar();
create function public.accesos_listar() returns table(id uuid, nombre text, cargo text, rol text, clave text, activo boolean, creado timestamptz)
language sql stable security definer set search_path = public as $$
  select a.id, a.nombre, a.cargo, a.rol, a.clave, a.activo, a.creado from public.accesos a
  where public.clave_rol() = 'admin' order by a.creado, a.nombre
$$;

drop function if exists public.acceso_crear(text, text);
create or replace function public.acceso_crear(p_nombre text, p_rol text default 'editor', p_cargo text default '', p_clave text default null) returns text
language plpgsql security definer set search_path = public as $$
declare h text; k text;
begin
  if public.clave_rol() is distinct from 'admin' then raise exception 'Solo un administrador puede crear claves'; end if;
  if coalesce(trim(p_nombre), '') = '' then raise exception 'Falta el nombre'; end if;
  if p_rol not in ('admin','editor','lectura') then raise exception 'Permiso no válido'; end if;
  k := nullif(trim(coalesce(p_clave, '')), '');
  if k is null then
    h := upper(replace(gen_random_uuid()::text, '-', ''));
    k := substr(h,1,4) || '-' || substr(h,5,4) || '-' || substr(h,9,4);
  else
    if k !~ '^[A-Za-z0-9-]{2,20}$' then raise exception 'La clave debe tener de 2 a 20 letras o números'; end if;
    k := upper(k);
  end if;
  if exists (select 1 from public.accesos where lower(clave) = lower(k)) then raise exception 'duplicate: esa clave ya existe'; end if;
  insert into public.accesos(clave, nombre, cargo, rol) values (k, trim(p_nombre), coalesce(trim(p_cargo), ''), p_rol);
  return k;
end $$;

grant execute on function public.clave_escribe(), public.accesos_listar(), public.acceso_crear(text, text, text, text) to anon, authenticated;

-- 3) Seguridad: leer = cualquier clave activa; escribir = Administrador o Editor
drop policy if exists "docs_clave" on public.docs;
drop policy if exists "docs_leer" on public.docs;
drop policy if exists "docs_insertar" on public.docs;
drop policy if exists "docs_modificar" on public.docs;
drop policy if exists "docs_borrar" on public.docs;
create policy "docs_leer" on public.docs for select to anon, authenticated using (public.clave_ok());
create policy "docs_insertar" on public.docs for insert to anon, authenticated with check (public.clave_escribe());
create policy "docs_modificar" on public.docs for update to anon, authenticated using (public.clave_escribe()) with check (public.clave_escribe());
create policy "docs_borrar" on public.docs for delete to anon, authenticated using (public.clave_escribe());
