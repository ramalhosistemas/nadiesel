const CACHE='na-diesel-v19';
self.addEventListener('install',event=>event.waitUntil(self.skipWaiting()));
self.addEventListener('activate',event=>event.waitUntil((async()=>{const keys=await caches.keys();await Promise.all(keys.filter(key=>key!==CACHE).map(key=>caches.delete(key)));await self.clients.claim()})()));
self.addEventListener('fetch',event=>{const request=event.request;if(request.method!=='GET'||request.url.includes('/api/'))return;event.respondWith((async()=>{try{const response=await fetch(request,{cache:'no-store'});if(response.ok){const cache=await caches.open(CACHE);await cache.put(request,response.clone())}return response}catch(error){const cached=await caches.match(request);if(cached)return cached;if(request.mode==='navigate')return caches.match('/');throw error}})())});
