-- =====================================================================
-- Dart Scorer: Server-Einrichtung (Supabase)
-- Einmal im Supabase-Dashboard unter "SQL Editor" einfügen und "Run" klicken.
-- Die App greift NUR über die unten angelegten Funktionen zu. Die Tabellen
-- selbst sind für Fremde gesperrt (Row Level Security ohne Regeln).
-- PINs werden nie im Klartext gespeichert (bcrypt-Hash).
-- =====================================================================

create extension if not exists pgcrypto with schema extensions;

-- ---------- Tabellen ----------
create table if not exists public.dart_players (
  id           uuid primary key default gen_random_uuid(),
  name         text not null,
  pin_hash     text not null,
  is_public    boolean not null default false,
  stats        jsonb not null default '{}'::jsonb,
  hist         jsonb not null default '[]'::jsonb,
  games        jsonb not null default '[]'::jsonb,
  fails        int not null default 0,
  locked_until timestamptz,
  created_at   timestamptz not null default now(),
  updated_at   timestamptz not null default now()
);
create unique index if not exists dart_players_name_key on public.dart_players (lower(name));

create table if not exists public.dart_sessions (
  token      uuid primary key default gen_random_uuid(),
  player_id  uuid not null references public.dart_players(id) on delete cascade,
  created_at timestamptz not null default now()
);

alter table public.dart_players  enable row level security;
alter table public.dart_sessions enable row level security;
revoke all on public.dart_players  from anon, authenticated;
revoke all on public.dart_sessions from anon, authenticated;

-- ---------- Hilfsfunktion (nicht von außen aufrufbar) ----------
create or replace function public.dart_player_from_token(p_token uuid)
returns uuid language sql security definer set search_path = public as $$
  select player_id from public.dart_sessions
  where token = p_token and created_at > now() - interval '90 days'
$$;
revoke all on function public.dart_player_from_token(uuid) from public, anon, authenticated;

-- ---------- Registrieren ----------
create or replace function public.dart_register(p_name text, p_pin text)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare v_name text := btrim(coalesce(p_name, '')); v_id uuid; v_tok uuid;
begin
  if char_length(v_name) < 2 or char_length(v_name) > 16 then return jsonb_build_object('error','bad_name'); end if;
  if p_pin is null or p_pin !~ '^[0-9]{6}$' then return jsonb_build_object('error','bad_pin'); end if;
  if exists (select 1 from public.dart_players where lower(name) = lower(v_name)) then
    return jsonb_build_object('error','name_taken');
  end if;
  insert into public.dart_players (name, pin_hash) values (v_name, crypt(p_pin, gen_salt('bf')))
    returning id into v_id;
  insert into public.dart_sessions (player_id) values (v_id) returning token into v_tok;
  return jsonb_build_object('id', v_id, 'name', v_name, 'token', v_tok, 'public', false);
exception when unique_violation then
  return jsonb_build_object('error','name_taken');
end $$;

-- ---------- Anmelden (5 Fehlversuche = 15 Minuten gesperrt) ----------
create or replace function public.dart_login(p_name text, p_pin text)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare r public.dart_players%rowtype; v_tok uuid;
begin
  select * into r from public.dart_players where lower(name) = lower(btrim(coalesce(p_name, '')));
  if not found then
    perform pg_sleep(0.4);
    return jsonb_build_object('error','bad_login');
  end if;
  if r.locked_until is not null and r.locked_until > now() then
    return jsonb_build_object('error','locked');
  end if;
  if p_pin is null or r.pin_hash <> crypt(p_pin, r.pin_hash) then
    update public.dart_players set
      fails        = case when fails + 1 >= 5 then 0 else fails + 1 end,
      locked_until = case when fails + 1 >= 5 then now() + interval '15 minutes' else locked_until end
    where id = r.id;
    return jsonb_build_object('error','bad_login');
  end if;
  update public.dart_players set fails = 0, locked_until = null where id = r.id;
  insert into public.dart_sessions (player_id) values (r.id) returning token into v_tok;
  delete from public.dart_sessions where created_at < now() - interval '90 days';
  return jsonb_build_object('id', r.id, 'name', r.name, 'token', v_tok, 'public', r.is_public);
end $$;

-- ---------- Eigenes Profil abrufen ----------
create or replace function public.dart_me(p_token uuid)
returns jsonb language plpgsql security definer set search_path = public as $$
declare v_id uuid := public.dart_player_from_token(p_token); r public.dart_players%rowtype;
begin
  if v_id is null then return jsonb_build_object('error','no_session'); end if;
  select * into r from public.dart_players where id = v_id;
  return jsonb_build_object('id', r.id, 'name', r.name, 'public', r.is_public,
                            'stats', r.stats, 'hist', r.hist, 'games', r.games);
end $$;

-- ---------- Statistik hochladen ----------
create or replace function public.dart_push(p_token uuid, p_stats jsonb, p_hist jsonb, p_games jsonb)
returns jsonb language plpgsql security definer set search_path = public as $$
declare v_id uuid := public.dart_player_from_token(p_token);
begin
  if v_id is null then return jsonb_build_object('error','no_session'); end if;
  if jsonb_typeof(p_stats) <> 'object' or jsonb_typeof(p_hist) <> 'array' or jsonb_typeof(p_games) <> 'array' then
    return jsonb_build_object('error','bad_data');
  end if;
  if length(p_stats::text) > 20000 or length(p_hist::text) > 400000 or length(p_games::text) > 20000 then
    return jsonb_build_object('error','too_big');
  end if;
  update public.dart_players
     set stats = p_stats, hist = p_hist, games = p_games, updated_at = now()
   where id = v_id;
  return jsonb_build_object('ok', true);
end $$;

-- ---------- Profil öffentlich / privat ----------
create or replace function public.dart_set_public(p_token uuid, p_public boolean)
returns jsonb language plpgsql security definer set search_path = public as $$
declare v_id uuid := public.dart_player_from_token(p_token);
begin
  if v_id is null then return jsonb_build_object('error','no_session'); end if;
  update public.dart_players set is_public = coalesce(p_public, false) where id = v_id;
  return jsonb_build_object('ok', true, 'public', coalesce(p_public, false));
end $$;

-- ---------- Liste aller öffentlichen Profile ----------
create or replace function public.dart_list_public()
returns jsonb language sql security definer set search_path = public as $$
  select coalesce(jsonb_agg(x order by lower(x->>'name')), '[]'::jsonb) from (
    select jsonb_build_object('id', id, 'name', name, 'x01', stats->'x01', 'updated', updated_at) as x
    from public.dart_players where is_public order by lower(name) limit 200
  ) t
$$;

-- ---------- Ein Profil ansehen (öffentlich, oder das eigene) ----------
create or replace function public.dart_get_profile(p_id uuid, p_token uuid default null)
returns jsonb language plpgsql security definer set search_path = public as $$
declare r public.dart_players%rowtype; v_me uuid := public.dart_player_from_token(p_token);
begin
  select * into r from public.dart_players where id = p_id;
  if not found or not (r.is_public or coalesce(v_me = r.id, false)) then return jsonb_build_object('error','not_found'); end if;
  return jsonb_build_object('id', r.id, 'name', r.name, 'public', r.is_public,
                            'stats', r.stats, 'hist', r.hist, 'games', r.games);
end $$;

-- ---------- PIN ändern ----------
create or replace function public.dart_change_pin(p_token uuid, p_old text, p_new text)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare v_id uuid := public.dart_player_from_token(p_token); r public.dart_players%rowtype;
begin
  if v_id is null then return jsonb_build_object('error','no_session'); end if;
  if p_new is null or p_new !~ '^[0-9]{6}$' then return jsonb_build_object('error','bad_pin'); end if;
  select * into r from public.dart_players where id = v_id;
  if r.locked_until is not null and r.locked_until > now() then return jsonb_build_object('error','locked'); end if;
  if p_old is null or r.pin_hash <> crypt(p_old, r.pin_hash) then
    update public.dart_players set
      fails        = case when fails + 1 >= 5 then 0 else fails + 1 end,
      locked_until = case when fails + 1 >= 5 then now() + interval '15 minutes' else locked_until end
    where id = v_id;
    return jsonb_build_object('error','bad_login');
  end if;
  update public.dart_players set pin_hash = crypt(p_new, gen_salt('bf')), fails = 0 where id = v_id;
  delete from public.dart_sessions where player_id = v_id and token <> p_token;
  return jsonb_build_object('ok', true);
end $$;

-- ---------- Abmelden ----------
create or replace function public.dart_logout(p_token uuid)
returns jsonb language plpgsql security definer set search_path = public as $$
begin
  delete from public.dart_sessions where token = p_token;
  return jsonb_build_object('ok', true);
end $$;

-- ---------- PIN-Reset durch den Administrator (nur im SQL Editor aufrufbar) ----------
-- Beispiel:  select public.dart_admin_reset_pin('Max', '123456');
create or replace function public.dart_admin_reset_pin(p_name text, p_pin text)
returns text language plpgsql security definer set search_path = public, extensions as $$
declare v_id uuid;
begin
  if p_pin is null or p_pin !~ '^[0-9]{6}$' then raise exception 'PIN muss aus genau 6 Ziffern bestehen'; end if;
  select id into v_id from public.dart_players where lower(name) = lower(btrim(p_name));
  if v_id is null then raise exception 'Benutzer nicht gefunden'; end if;
  update public.dart_players set pin_hash = crypt(p_pin, gen_salt('bf')), fails = 0, locked_until = null where id = v_id;
  delete from public.dart_sessions where player_id = v_id;
  return 'PIN zurückgesetzt für ' || p_name;
end $$;
revoke all on function public.dart_admin_reset_pin(text, text) from public, anon, authenticated;

-- ---------- Rechte: die App darf nur diese Funktionen aufrufen ----------
grant execute on function public.dart_register(text, text)                    to anon, authenticated;
grant execute on function public.dart_login(text, text)                       to anon, authenticated;
grant execute on function public.dart_me(uuid)                                to anon, authenticated;
grant execute on function public.dart_push(uuid, jsonb, jsonb, jsonb)         to anon, authenticated;
grant execute on function public.dart_set_public(uuid, boolean)               to anon, authenticated;
grant execute on function public.dart_list_public()                           to anon, authenticated;
grant execute on function public.dart_get_profile(uuid, uuid)                 to anon, authenticated;
grant execute on function public.dart_change_pin(uuid, text, text)            to anon, authenticated;
grant execute on function public.dart_logout(uuid)                            to anon, authenticated;
