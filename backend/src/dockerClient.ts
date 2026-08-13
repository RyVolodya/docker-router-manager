import http from "node:http";

const socketPath = process.env.DOCKER_SOCKET ?? "/var/run/docker.sock";

export async function dockerGet<T>(path: string): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const req = http.request(
      { socketPath, path, method: "GET", headers: { Host: "localhost" } },
      (res) => {
        let body = "";
        res.setEncoding("utf8");
        res.on("data", (chunk) => (body += chunk));
        res.on("end", () => {
          const statusCode = res.statusCode ?? 500;
          if (statusCode < 200 || statusCode >= 300) {
            reject(new Error(`Docker API HTTP ${statusCode}: ${body}`));
            return;
          }
          try {
            resolve(JSON.parse(body) as T);
          } catch (error) {
            reject(new Error(`Invalid Docker API JSON: ${String(error)}`));
          }
        });
      }
    );
    req.on("error", reject);
    req.end();
  });
}
