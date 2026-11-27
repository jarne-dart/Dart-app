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


-- =====================================================================
-- ERWEITERUNG 2: Charakter, Battle Pass und "The 100"
-- (darf mehrfach ausgeführt werden)
-- =====================================================================

-- ---------- Charakter und Battle Pass pro Konto ----------
alter table public.dart_players add column if not exists skin jsonb not null default '{}'::jsonb;
alter table public.dart_players add column if not exists bp   jsonb not null default '{}'::jsonb;

create or replace function public.dart_me(p_token uuid)
returns jsonb language plpgsql security definer set search_path = public as $$
declare v_id uuid := public.dart_player_from_token(p_token); r public.dart_players%rowtype;
begin
  if v_id is null then return jsonb_build_object('error','no_session'); end if;
  select * into r from public.dart_players where id = v_id;
  return jsonb_build_object('id', r.id, 'name', r.name, 'public', r.is_public,
                            'stats', r.stats, 'hist', r.hist, 'games', r.games,
                            'skin', r.skin, 'bp', r.bp);
end $$;

create or replace function public.dart_push_char(p_token uuid, p_skin jsonb, p_bp jsonb)
returns jsonb language plpgsql security definer set search_path = public as $$
declare v_id uuid := public.dart_player_from_token(p_token);
begin
  if v_id is null then return jsonb_build_object('error','no_session'); end if;
  if jsonb_typeof(p_skin) <> 'object' or jsonb_typeof(p_bp) <> 'object' then return jsonb_build_object('error','bad_data'); end if;
  if length(p_skin::text) > 2000 or length(p_bp::text) > 4000 then return jsonb_build_object('error','too_big'); end if;
  update public.dart_players set skin = p_skin, bp = p_bp where id = v_id;
  return jsonb_build_object('ok', true);
end $$;

create or replace function public.dart_get_profile(p_id uuid, p_token uuid default null)
returns jsonb language plpgsql security definer set search_path = public as $$
declare r public.dart_players%rowtype; v_me uuid := public.dart_player_from_token(p_token);
begin
  select * into r from public.dart_players where id = p_id;
  if not found or not (r.is_public or coalesce(v_me = r.id, false)) then return jsonb_build_object('error','not_found'); end if;
  return jsonb_build_object('id', r.id, 'name', r.name, 'public', r.is_public,
                            'stats', r.stats, 'hist', r.hist, 'games', r.games,
                            'skin', r.skin, 'bp', jsonb_build_object('pts', coalesce(r.bp->'pts', '0'::jsonb)));
end $$;

grant execute on function public.dart_push_char(uuid, jsonb, jsonb) to anon, authenticated;

-- ---------- The 100: Tabelle ----------
create table if not exists public.dart100_runs (
  id           bigserial primary key,
  player_id    uuid not null references public.dart_players(id) on delete cascade,
  day          date not null,
  kind         text not null,
  targets      jsonb not null,
  started_at   timestamptz not null default now(),
  submitted_at timestamptz,
  result       jsonb,
  score        int,
  darts        int,
  secs         int,
  unique (player_id, day)
);
alter table public.dart100_runs enable row level security;
revoke all on public.dart100_runs from anon, authenticated;

-- ---------- The 100: Hilfsfunktionen (nicht von außen aufrufbar) ----------
-- Zeitfenster: Starten kann man jeden Tag zwischen 12:00 und 23:59 Uhr (deutsche Zeit).
-- Ab dem Start hat jeder Spieler genau eine Stunde am Stück (siehe dart100_start / dart100_submit).
create or replace function public.dart100_now() returns timestamptz
language sql stable as $$ select now() $$;

create or replace function public.dart100_today() returns date
language sql stable as $$ select (public.dart100_now() at time zone 'Europe/Berlin')::date $$;

create or replace function public.dart100_opens(p_day date) returns timestamptz
language sql immutable as $$ select ((p_day + time '12:00') at time zone 'Europe/Berlin') $$;

create or replace function public.dart100_closes(p_day date) returns timestamptz
language sql immutable as $$ select (((p_day + 1) + time '00:00') at time zone 'Europe/Berlin') $$;

-- Ab hier ist der Tag endgültig gewertet (letzter Start 23:59 + eine Stunde)
create or replace function public.dart100_final(p_day date) returns timestamptz
language sql immutable as $$ select public.dart100_closes(p_day) + interval '1 hour' $$;

-- Spielart des Tages: Finish-Folge, Score-Jagd, Doppel-Training im Wechsel
create or replace function public.dart100_kind(p_day date) returns text
language sql immutable as $$ select (array['finish','score','doubles'])[((p_day - date '2025-01-01') % 3) + 1] $$;

-- Aufgaben des Tages (für alle gleich, aus dem Datum abgeleitet)
create or replace function public.dart100_targets(p_day date) returns jsonb
language plpgsql immutable as $$
declare k text := public.dart100_kind(p_day); pools int[][] ; out jsonb := '[]'::jsonb; i int; v int;
begin
  if k = 'finish' then
    pools := array[
      array[24,28,32,36,40], array[44,48,52,56,60], array[61,64,66,68,70], array[72,74,76,78,80],
      array[81,84,86,88,90], array[92,94,96,98,100], array[101,104,106,108,110], array[112,114,116,118,120],
      array[121,124,126,128,130], array[132,136,140,144,150]];
    for i in 1..10 loop
      v := pools[i][1 + (get_byte(decode(md5(p_day::text || ':' || i), 'hex'), 0) % 5)];
      out := out || to_jsonb(v);
    end loop;
  elsif k = 'doubles' then
    select coalesce(jsonb_agg(d order by h), '[]'::jsonb) into out from (
      select d, md5(p_day::text || ':' || d) as h from unnest(array[2,4,6,8,10,12,14,16,18,20,22,24,26,28,30,32,34,36,38,40,50]) d
      order by md5(p_day::text || ':' || d) limit 10) t;
  else
    out := '[0,0,0,0,0,0,0,0,0,0]'::jsonb;  -- Score-Jagd: 10 Aufnahmen
  end if;
  return out;
end $$;

-- Wie viele Darts braucht man mindestens für dieses Finish? (3 = alles bis 170)
create or replace function public.dart100_min_darts(p_s int) returns int
language sql immutable as $$
  with v as (select x from unnest(array[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,25,
        2,4,6,8,10,12,14,16,18,20,22,24,26,28,30,32,34,36,38,40,50,
        3,6,9,12,15,18,21,24,27,30,33,36,39,42,45,48,51,54,57,60]) x group by x),
       d as (select x from v where x in (2,4,6,8,10,12,14,16,18,20,22,24,26,28,30,32,34,36,38,40,50))
  select case
    when p_s in (select x from d) then 1
    when exists (select 1 from v, d where v.x + d.x = p_s) then 2
    when p_s between 3 and 170 and exists (select 1 from v a, v b, d where a.x + b.x + d.x = p_s) then 3
    else 99 end
$$;

-- Unmögliche 3-Dart-Scores
create or replace function public.dart100_score_ok(p_s int) returns boolean
language sql immutable as $$ select p_s between 0 and 180 and p_s <> all (array[163,166,169,172,173,175,176,178,179]) $$;

-- Punkte pro Tag (nur für beendete Tage): Platz 1 = 100, Platz 2 = 99, ... bis 0
create or replace function public.dart100_points_all()
returns table(day date, player_id uuid, rk bigint, pts int)
language sql stable as $$
  select r.day, r.player_id, r.rk, greatest(0, 101 - r.rk::int)
  from (select x.day, x.player_id,
               row_number() over (partition by x.day order by x.score desc, x.darts asc, x.secs asc, x.submitted_at asc) as rk
        from public.dart100_runs x
        where x.submitted_at is not null and public.dart100_final(x.day) <= public.dart100_now()) r
$$;

revoke all on function public.dart100_now(), public.dart100_today(), public.dart100_opens(date), public.dart100_closes(date),
  public.dart100_final(date), public.dart100_kind(date), public.dart100_targets(date), public.dart100_min_darts(int), public.dart100_score_ok(int),
  public.dart100_points_all() from public, anon, authenticated;

-- ---------- The 100: Stand abrufen (Zeitfenster, Rangliste, mein Ergebnis) ----------
create or replace function public.dart100_status(p_token uuid default null)
returns jsonb language plpgsql security definer set search_path = public as $$
declare
  v_me uuid := public.dart_player_from_token(p_token);
  v_now timestamptz := public.dart100_now(); v_day date := public.dart100_today();
  v_open timestamptz := public.dart100_opens(v_day); v_close timestamptz := public.dart100_closes(v_day);
  v_state text; v_run public.dart100_runs%rowtype; v_my jsonb := 'null'::jsonb;
  v_lb jsonb; v_month jsonb; v_mm jsonb := 'null'::jsonb; v_ms date := date_trunc('month', v_day)::date;
begin
  v_state := case when v_now < v_open then 'before' when v_now < v_close then 'open' else 'closed' end;
  if v_me is not null then
    select * into v_run from public.dart100_runs
     where player_id = v_me and submitted_at is null and started_at > v_now - interval '1 hour'
     order by started_at desc limit 1;
    if not found then
      select * into v_run from public.dart100_runs where player_id = v_me and day = v_day;
    end if;
    if found then
      v_my := jsonb_build_object('day', v_run.day, 'started', true, 'submitted', v_run.submitted_at is not null,
                                 'score', v_run.score, 'darts', v_run.darts, 'secs', v_run.secs,
                                 'started_at', v_run.started_at, 'ends_at', v_run.started_at + interval '1 hour');
    else v_my := jsonb_build_object('started', false, 'submitted', false);
    end if;
  end if;
  -- Tagesrangliste (vorläufig, solange das Fenster offen ist)
  select coalesce(jsonb_agg(jsonb_build_object('rank', rk, 'name', name, 'score', score, 'darts', darts, 'secs', secs,
                   'pts', greatest(0, 101 - rk), 'me', pid = v_me) order by rk), '[]'::jsonb) into v_lb from (
    select row_number() over (order by x.score desc, x.darts asc, x.secs asc, x.submitted_at asc) as rk,
           p.name, x.score, x.darts, x.secs, x.player_id as pid
    from public.dart100_runs x join public.dart_players p on p.id = x.player_id
    where x.day = v_day and x.submitted_at is not null limit 30) t;
  -- Monatswertung (nur beendete Tage)
  with m as (select a.player_id, sum(a.pts)::int as pts, count(*)::int as days, count(*) filter (where a.rk = 1)::int as wins
             from public.dart100_points_all() a
             where a.day >= v_ms and a.day < (v_ms + interval '1 month')::date group by a.player_id),
       rk as (select m.*, p.name, row_number() over (order by m.pts desc, m.wins desc, p.name) as pos
              from m join public.dart_players p on p.id = m.player_id)
  select coalesce(jsonb_agg(jsonb_build_object('rank', pos, 'name', name, 'pts', pts, 'days', days, 'wins', wins, 'me', player_id = v_me) order by pos)
                  filter (where pos <= 30), '[]'::jsonb),
         coalesce((select jsonb_build_object('rank', pos, 'pts', pts, 'days', days) from rk where player_id = v_me), 'null'::jsonb)
    into v_month, v_mm from rk;
  return jsonb_build_object('now', v_now, 'day', v_day, 'opens', v_open, 'closes', v_close, 'state', v_state,
    'kind', public.dart100_kind(v_day), 'opens_txt', to_char(v_open at time zone 'Europe/Berlin', 'HH24:MI'),
    'closes_txt', to_char((v_close - interval '1 minute') at time zone 'Europe/Berlin', 'HH24:MI'),
    'month', to_char(v_ms, 'YYYY-MM'), 'my', v_my, 'lb', v_lb, 'ranking', v_month, 'my_month', v_mm);
end $$;

-- ---------- The 100: Versuch starten (pro Tag nur einmal, nur im Zeitfenster) ----------
create or replace function public.dart100_start(p_token uuid)
returns jsonb language plpgsql security definer set search_path = public as $$
declare v_me uuid := public.dart_player_from_token(p_token); v_now timestamptz := public.dart100_now();
        v_day date := public.dart100_today(); v_run public.dart100_runs%rowtype;
begin
  if v_me is null then return jsonb_build_object('error','no_session'); end if;
  -- laufender Versuch (auch über Mitternacht hinweg)? Dann einfach fortsetzen
  select * into v_run from public.dart100_runs
   where player_id = v_me and submitted_at is null and started_at > v_now - interval '1 hour'
   order by started_at desc limit 1;
  if found then
    return jsonb_build_object('ok', true, 'resume', true, 'day', v_run.day, 'kind', v_run.kind, 'targets', v_run.targets,
                              'now', v_now, 'started_at', v_run.started_at, 'ends_at', v_run.started_at + interval '1 hour');
  end if;
  select * into v_run from public.dart100_runs where player_id = v_me and day = v_day;
  if found then
    if v_run.submitted_at is not null then return jsonb_build_object('error','already_done'); end if;
    return jsonb_build_object('error','expired');
  end if;
  if v_now < public.dart100_opens(v_day) then return jsonb_build_object('error','too_early'); end if;
  if v_now >= public.dart100_closes(v_day) then return jsonb_build_object('error','closed'); end if;
  insert into public.dart100_runs (player_id, day, kind, targets, started_at)
    values (v_me, v_day, public.dart100_kind(v_day), public.dart100_targets(v_day), v_now)
    returning * into v_run;
  return jsonb_build_object('ok', true, 'resume', false, 'day', v_run.day, 'kind', v_run.kind, 'targets', v_run.targets,
                            'now', v_now, 'started_at', v_run.started_at, 'ends_at', v_run.started_at + interval '1 hour');
end $$;

-- ---------- The 100: Ergebnis abgeben (wird auf Plausibilität geprüft) ----------
-- finish/doubles: [{"h":true,"d":2}, ...] (10 Einträge)   score: [60,100,...] (10 Aufnahmen)
create or replace function public.dart100_submit(p_token uuid, p_result jsonb)
returns jsonb language plpgsql security definer set search_path = public as $$
declare v_me uuid := public.dart_player_from_token(p_token); v_now timestamptz := public.dart100_now();
        v_run public.dart100_runs%rowtype; i int; e jsonb; t int; d int; v_score int := 0; v_darts int := 0; v_secs int;
begin
  if v_me is null then return jsonb_build_object('error','no_session'); end if;
  select * into v_run from public.dart100_runs
   where player_id = v_me and submitted_at is null order by started_at desc limit 1 for update;
  if not found then
    if exists (select 1 from public.dart100_runs where player_id = v_me and day = public.dart100_today()) then
      return jsonb_build_object('error','already_done'); end if;
    return jsonb_build_object('error','no_run');
  end if;
  if v_now > v_run.started_at + interval '1 hour' then return jsonb_build_object('error','expired'); end if;
  if jsonb_typeof(p_result) <> 'array' or jsonb_array_length(p_result) <> 10 then return jsonb_build_object('error','bad_result'); end if;
  for i in 0..9 loop
    e := p_result -> i;
    if v_run.kind = 'score' then
      if jsonb_typeof(e) <> 'number' then return jsonb_build_object('error','bad_result'); end if;
      t := (e #>> '{}')::numeric::int;
      if (e #>> '{}')::numeric <> t or not public.dart100_score_ok(t) then return jsonb_build_object('error','bad_result'); end if;
      v_score := v_score + t; v_darts := v_darts + 3;
    else
      if jsonb_typeof(e) <> 'object' or jsonb_typeof(e->'h') <> 'boolean' or jsonb_typeof(e->'d') <> 'number' then
        return jsonb_build_object('error','bad_result'); end if;
      d := (e->>'d')::numeric::int; t := (v_run.targets ->> i)::int;
      if d < 1 or d > 3 then return jsonb_build_object('error','bad_result'); end if;
      if (e->>'h')::boolean then
        if d < public.dart100_min_darts(t) then return jsonb_build_object('error','bad_result'); end if;
        v_score := v_score + 1;
      elsif d <> 3 then return jsonb_build_object('error','bad_result');
      end if;
      v_darts := v_darts + d;
    end if;
  end loop;
  v_secs := greatest(1, extract(epoch from (v_now - v_run.started_at))::int);
  if v_secs < v_darts * 4 then return jsonb_build_object('error','too_fast'); end if;
  update public.dart100_runs set submitted_at = v_now, result = p_result, score = v_score, darts = v_darts, secs = v_secs
   where id = v_run.id;
  return jsonb_build_object('ok', true, 'score', v_score, 'darts', v_darts, 'secs', v_secs);
end $$;

-- ---------- The 100: Monatsbelohnungen (Platz 1 bis 3 der abgeschlossenen Monate) ----------
create or replace function public.dart100_rewards(p_token uuid)
returns jsonb language plpgsql security definer set search_path = public as $$
declare v_me uuid := public.dart_player_from_token(p_token); out jsonb;
begin
  if v_me is null then return jsonb_build_object('error','no_session'); end if;
  with m as (select date_trunc('month', a.day)::date as mon, a.player_id, sum(a.pts)::int as pts, count(*) filter (where a.rk = 1) as wins
             from public.dart100_points_all() a group by 1, 2),
       r as (select mon, player_id, pts, row_number() over (partition by mon order by pts desc, wins desc, player_id) as pos from m)
  select coalesce(jsonb_agg(jsonb_build_object('month', to_char(mon, 'YYYY-MM'), 'rank', pos, 'pts', pts) order by mon), '[]'::jsonb)
    into out from r
   where player_id = v_me and pos <= 3 and mon < date_trunc('month', public.dart100_today())::date;
  return jsonb_build_object('ok', true, 'rewards', out);
end $$;

grant execute on function public.dart100_status(uuid)         to anon, authenticated;
grant execute on function public.dart100_start(uuid)          to anon, authenticated;
grant execute on function public.dart100_submit(uuid, jsonb)  to anon, authenticated;
grant execute on function public.dart100_rewards(uuid)        to anon, authenticated;
