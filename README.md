# Quackback — backend en Pterodactyl + espejo web en Vercel

```
Navegador ──HTTPS──▶ Vercel (api/gateway.js) ══ AES-256-GCM sobre HTTP/HTTPS ══▶ Pterodactyl (index.js)
                      cifra petición                                          gateway :SERVER_PORT
                      descifra respuesta                                      └─▶ Quackback 127.0.0.1:3000
```

## 0. Requisitos externos (Pterodactyl no los incluye)
- **PostgreSQL con pgvector** (Neon o Supabase lo traen). Las migraciones crean índices HNSW.
- **Redis** compatible con BullMQ (Redis propio o Upstash con URL `rediss://`).
- Contenedor Pterodactyl **Debian/Ubuntu (glibc)** con Node ≥ 20, `git` y **~2 GB de RAM** durante el primer build.

## 1. Backend (Pterodactyl)
1. Egg "Node.js generic". Sube la carpeta `backend/` al servidor.
2. Startup file / comando: `node index.js`
3. Copia `.env.example` a `.env` y rellénalo. Genera secretos:
   - `node index.js --gen-secret` → `TUNNEL_SECRET`
   - `openssl rand -base64 32` → `SECRET_KEY`
4. `BASE_URL` = dominio de Vercel (ej. `https://feedback.tudominio.com`).
5. Asigna una allocation y arranca. Primer arranque: instala Bun, clona, compila, migra y abre el gateway.

## 2. Vercel
1. Sube `vercel/` a un repo (o `vercel deploy` desde esa carpeta).
2. Variables de entorno: `ORIGIN_URL=http://IP:PUERTO`, `TUNNEL_SECRET=<el mismo>`.
3. Despliega y, si quieres, añade tu dominio. Ese dominio debe coincidir con `BASE_URL`.

## Bun y Node
Bun no puede "vivir dentro" de Node (son runtimes distintos); `index.js` (Node) descarga el binario de Bun vía npm y lo lanza como subproceso.
Con `RUNTIME=node` la app se **sirve con Node**; Bun solo se usa para `install`, `build` y migraciones. Experimental: si Quackback usa APIs exclusivas de Bun, el arranque falla y `index.js` vuelve a Bun automáticamente.

## Cómo funciona la seguridad
- AES-256-GCM, claves derivadas con HKDF de `TUNNEL_SECRET`; solo quien tenga el secreto descifra o forja peticiones.
- Claves distintas para petición y respuesta; la respuesta va ligada al nonce de su petición.
- Timestamp (±60 s) + nonce de un solo uso → sin replay.
- El gateway responde **404 vacío** a todo lo que no sea un frame válido: la app no es accesible directamente.
- Opcional: `TLS_CERT`/`TLS_KEY` para HTTPS en el gateway (útil para ocultar metadatos como tamaños y timing).

## Limitaciones conocidas
- **Sin SSE/WebSockets**: se fuerza `CHAT_TRANSPORT_MODE=poll`.
- Cuerpos de petición ≤ ~4 MB (límite de Vercel): subidas grandes de imágenes pueden fallar.
- Cada asset pasa por una función de Vercel (se cachean los de `/assets/` en su CDN).
- Todo el tráfico consume invocaciones/ancho de banda de Vercel (cuidado con el plan Hobby).
- Licencia AGPL-3.0: si modificas Quackback y lo ofreces como servicio, debes publicar los cambios.
