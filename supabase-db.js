/* Capa de datos sobre Supabase con la misma interfaz que usa la app (collection/doc/where/onSnapshot).
   Todo se guarda en una sola tabla: docs(coll, id, data). */
window.makeSupabaseDb = function (sb) {
  const T = "docs";
  const snapOf = (id, row) => ({ id, exists: !!row, data: () => (row ? row.data : undefined), metadata: { fromCache: false, hasPendingWrites: false } });
  const qsnap = rows => ({ docs: rows.map(r => snapOf(r.id, r)), empty: !rows.length, metadata: { fromCache: false, hasPendingWrites: false } });
  const fail = r => { if (r.error) throw r.error; return r; };

  function watch(coll, refetch, cb, err) {
    let stop = false, t = null;
    const run = () => refetch().then(s => { if (!stop) cb(s); }).catch(e => { if (!stop && err) err(e); });
    run();
    const ch = sb.channel("w-" + coll + "-" + Math.random().toString(36).slice(2))
      .on("postgres_changes", { event: "*", schema: "public", table: T, filter: "coll=eq." + coll }, () => { clearTimeout(t); t = setTimeout(run, 150); })
      .subscribe();
    return () => { stop = true; clearTimeout(t); sb.removeChannel(ch); };
  }

  function docRef(coll, id) {
    const get = async () => { const r = fail(await sb.from(T).select("id,data").eq("coll", coll).eq("id", id).maybeSingle()); return snapOf(id, r.data); };
    return {
      id,
      get,
      set: async data => { fail(await sb.from(T).upsert({ coll, id, data, updated_at: new Date().toISOString() })); },
      delete: async () => { fail(await sb.from(T).delete().eq("coll", coll).eq("id", id)); },
      onSnapshot: (cb, err) => watch(coll, get, cb, err),
      collection: name => collRef(coll + "/" + id + "/" + name)
    };
  }

  function collRef(coll, filters = [], lim = 1000) {
    const fetchAll = async () => {
      let q = sb.from(T).select("id,data").eq("coll", coll);
      for (const [f, op, v] of filters) {
        const col = "data->>" + f;
        q = op === "==" ? q.eq(col, v) : op === ">=" ? q.gte(col, v) : op === "<=" ? q.lte(col, v) : op === ">" ? q.gt(col, v) : q.lt(col, v);
      }
      return qsnap(fail(await q.limit(lim)).data || []);
    };
    return {
      doc: id => docRef(coll, id),
      where: (f, op, v) => collRef(coll, [...filters, [f, op, v]], lim),
      limit: n => collRef(coll, filters, n),
      get: fetchAll,
      onSnapshot: (cb, err) => watch(coll, fetchAll, cb, err)
    };
  }

  return {
    collection: collRef,
    doc: path => { const p = path.split("/"), id = p.pop(); return docRef(p.join("/"), id); }
  };
};
