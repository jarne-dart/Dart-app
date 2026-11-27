/* Service Worker: legt die App im Cache ab, damit sie ohne Internet startet.
   Beim Ändern der App die Version erhöhen (v1 -> v2), dann laden die Geräte die neue Datei. */
const CACHE='dart-v8';
const CORE=['./','index.html','config.js','manifest.webmanifest','icon-192.png','icon-512.png'];
self.addEventListener('install',e=>{
  e.waitUntil(caches.open(CACHE).then(c=>Promise.all(CORE.map(u=>c.add(u).catch(()=>{})))).then(()=>self.skipWaiting()));
});
self.addEventListener('activate',e=>{
  e.waitUntil(caches.keys().then(ks=>Promise.all(ks.filter(k=>k!==CACHE&&k!=='dart-model').map(k=>caches.delete(k)))).then(()=>self.clients.claim()));
});
self.addEventListener('fetch',e=>{
  const r=e.request;
  if(r.method!=='GET') return;
  const u=new URL(r.url);
  const same=u.origin===location.origin,cdn=u.hostname==='cdn.jsdelivr.net'&&u.pathname.includes('vosk');
  if(!same&&!cdn) return;                       // alles andere (z. B. Online-Spiel) nie anfassen
  const heavy=cdn||/\/models\/|\/vosk\.js$/.test(u.pathname);
  const store=res=>{if(res&&(res.ok||res.type==='opaque')){const cp=res.clone();caches.open(CACHE).then(c=>c.put(r,cp)).catch(()=>{});}return res;};
  if(heavy){
    e.respondWith(caches.match(r).then(m=>m||fetch(r).then(store)));
  } else {
    e.respondWith(fetch(r).then(store).catch(()=>caches.match(r).then(m=>m||caches.match('index.html'))));
  }
});
