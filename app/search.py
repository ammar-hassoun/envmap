"""Global search across projects, regions, environments, services and config keys."""
from . import repo, store

MAX_PER_KIND = 40


def search(q: str) -> dict:
    q = (q or "").strip().lower()
    if len(q) < 2:
        return {"query": q, "groups": [], "total": 0}

    services, configs, secrets, envs, clusters = [], [], [], [], []

    for pid, p in store.projects().items():
        pname = p.get("name", "")
        for cid, c in p.get("clusters", {}).items():
            if q in c.get("name", "").lower() or q in c.get("context", "").lower():
                clusters.append({"label": c["name"],
                                 "sub": f"{pname} · context {c.get('context') or '—'}",
                                 "url": f"/clusters#{cid}"})

        for rgid, rg in p.get("regions", {}).items():
            rname = rg.get("name", "")
            for env, files in repo.list_envs(pid, rgid, include_hidden=True).items():
                base = f"/p/{pid}/{rgid}/{env}"
                if q in env.lower():
                    envs.append({"label": f"{pname} · {rname} · {env}",
                                 "sub": f"{len(files)} services", "url": base})
                for f in files:
                    disp = repo.display(pid, f)
                    if q in disp.lower():
                        services.append({"label": disp,
                                         "sub": f"{pname} · {rname} · {env}",
                                         "url": f"{base}/s/{f}"})
                    if len(configs) + len(secrets) > 2 * MAX_PER_KIND:
                        continue
                    try:
                        d = repo.load_service(pid, rgid, env, f)
                    except Exception:
                        continue
                    for k, v in {**d["service_config"], **d["platform_config"]}.items():
                        ks, vs = str(k), str(v)
                        if q in ks.lower() or q in vs.lower():
                            configs.append({
                                "label": ks,
                                "sub": f"{disp} · {pname}/{rname}/{env}",
                                "extra": vs[:90],
                                "url": f"{base}/s/{f}#cfg_{ks}"})
                    for k in d["secret_keys"]:
                        if q in str(k).lower():
                            secrets.append({
                                "label": f"🔒 {k}",
                                "sub": f"{disp} · {pname}/{rname}/{env}",
                                "url": f"{base}/s/{f}"})

    groups = []
    for title, items in (("Services", services), ("Config keys", configs),
                         ("Secret keys", secrets), ("Environments", envs),
                         ("Clusters", clusters)):
        if items:
            groups.append({"title": title, "hits": items[:MAX_PER_KIND],
                           "more": max(0, len(items) - MAX_PER_KIND)})
    return {"query": q, "groups": groups,
            "total": sum(len(g["hits"]) for g in groups)}
