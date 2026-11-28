const VERSION="ghostcorp-vr-v1";
const PRECACHE=[
 "./",
 "./index.html",
 "./chat.html",
 "./action-center.html",
 "./project-board.html",
 "./manifest.webmanifest",
 "./icon.svg"
];
self.addEventListener("install",event=>{
 event.waitUntil(caches.open(VERSION).then(cache=>cache.addAll(PRECACHE)).then(()=>self.skipWaiting()));
});
self.addEventListener("activate",event=>{
 event.waitUntil(caches.keys().then(keys=>Promise.all(keys.filter(key=>key.startsWith("ghostcorp-vr-")&&key!==VERSION).map(key=>caches.delete(key)))).then(()=>self.clients.claim()));
});
self.addEventListener("message",event=>{
 if(event.data==="SKIP_WAITING")self.skipWaiting();
});
self.addEventListener("fetch",event=>{
 const request=event.request;
 if(request.method!=="GET")return;
 const url=new URL(request.url);
 if(url.origin===self.location.origin && (url.pathname.startsWith("/api/")||url.pathname.startsWith("/auth/")))return;
 if(request.mode==="navigate"){
  event.respondWith(fetch(request).then(response=>{
   if(response.ok){const copy=response.clone();caches.open(VERSION).then(cache=>cache.put(request,copy));}
   return response;
  }).catch(()=>caches.match(request).then(hit=>hit||caches.match("./index.html"))));
  return;
 }
 const cacheable=(url.origin===self.location.origin)||(/cdn\.jsdelivr\.net$/.test(url.hostname)&&request.destination==="script");
 if(!cacheable)return;
 event.respondWith(caches.match(request).then(cached=>{
  const network=fetch(request).then(response=>{
   if(response.ok && (response.type==="basic"||response.type==="cors"))caches.open(VERSION).then(cache=>cache.put(request,response.clone()));
   return response;
  });
  return cached||network;
 }));
});
