# BountyTrack — Write-up Analiz Modülü (Spec)

> Bu dosya, modülün tasarım kararlarını ve MVP planını içerir. Claude Code için talimat: **önce mevcut BountyTrack repo yapısını ve konvansiyonlarını incele, sonra bu spec'e göre 1. haftadan başla.** "Doğrula" diye işaretlenen her şeyi resmi dokümandan kontrol et, tahminle yazma.

---

## 1. Amaç

HackerOne (ileride Bugcrowd, Medium vb.) üzerindeki **yeni açıklanmış (disclosed) bug bounty raporlarını** otomatik çekip, kullanıcıya **zafiyetin neden oluştuğunu** açıklayan bir modül.

**Fark yaratan açı (özetleyici değil, purple team öğrenme aracı):**
- **Kök neden:** Geliştiricinin yaptığı yanlış varsayım (zafiyet adını tekrar etmek değil)
- **Saldırı akışı:** Her adımda "bu neden çalışıyor?"
- **Düzeltme:** Yanlış yaklaşım ve doğru yaklaşım, mümkünse kod ipucu
- **Tespit:** Log / WAF / uygulama izlemede nasıl yakalanır (blue team tarafı)
- **Test checklist'i:** "Kendi hedefinde bunu nasıl ararsın"
- İçerik Türkçe, teknik terimler İngilizce (IDOR, payload, endpoint)

Piyasada sadece özetleyen araçlar var (HackerOne Hai, Bugcrowd AI Triage, "Bug Insider" GPT, GitHub'daki bug-bounty-summaries). Fark: kök neden + tespit + pratik checklist + Türkçe + BountyTrack entegrasyonu.

---

## 2. Alınan kararlar

| Konu | Karar |
|---|---|
| Ürün konumu | Ayrı uygulama değil, **BountyTrack modülü** (tek auth, tek DB) |
| Stack | Next.js + Supabase (BountyTrack'in mevcut stack'i) |
| LLM maliyeti | **BYOK**: Her kullanıcı kendi API key'ini girer |
| Varsayılan sağlayıcı | **Google Gemini** (sahibi bunu kullanacak). İlk yazılacak adaptör bu |
| Erişim | **Kapalı**: modül giriş yapan kullanıcıya özel. Ayrıca birkaç örnek analizin yer aldığı **public bir vitrin sayfası** (SEO ve tanıtım için) |
| İlk kaynak | Sadece HackerOne Hacktivity (disclosed) |

---

## 3. Mimari

BYOK olduğu için merkezi pipeline LLM **kullanmaz**.

```
[MERKEZİ — cron, günde 1, LLM yok, maliyet yok]
  Fetch (HackerOne, disclosed) → Dedupe (source+external_id, content_hash)
  → Heuristik kalite filtresi (metin uzunluğu, adım/istek/payload var mı) → writeups tablosu

[KULLANICI — isteğe bağlı, kullanıcının kendi key'iyle]
  "Analiz et" (tekil) veya toplu ("bu haftanın IDOR'ları")
  → analysis_jobs kuyruğu (rate limit'e uygun, sıralı)
  → (toplu modda) Triage: ucuz model (Gemini Flash), kalite 0-10 + vuln_class; <5 ise atla
  → Deep analysis: güçlü model (Gemini Pro), yapılandırılmış JSON
  → zod doğrulama → geçmezse 1 kez tekrar dene → yine olmazsa 'failed'
  → analyses tablosu (user_id'ye bağlı önbellek)
```

- **Önbellek:** Aynı kullanıcı aynı raporu tekrar analiz ettirmez. Analizler varsayılan olarak **kullanıcıya özeldir**. Bir kullanıcının parasıyla üretilen analizi başkalarına otomatik gösterme. İleride "toplulukla paylaş" seçeneği eklenebilir.
- **Çalışma yeri:** Supabase Edge Function + `pg_cron`. Timeout sorun olursa GitHub Actions cron + Node script'i.

---

## 4. Veri modeli (taslak, mevcut şemaya uyarla)

```sql
create table writeups (
  id            uuid primary key default gen_random_uuid(),
  source        text not null,                 -- 'hackerone'
  external_id   text not null,
  url           text not null,
  title         text not null,
  program       text,
  weakness      text,                          -- platformun verdiği CWE/weakness
  severity      text,
  bounty        numeric,
  disclosed_at  timestamptz,
  raw_text      text,                          -- SADECE analiz için; UI'da gösterilmez
  content_hash  text not null,
  quality_flag  text not null default 'ok',    -- ok | low (heuristik filtre)
  created_at    timestamptz default now(),
  unique (source, external_id)
);
create index on writeups (disclosed_at desc);

create table analyses (
  id              uuid primary key default gen_random_uuid(),
  writeup_id      uuid not null references writeups(id) on delete cascade,
  user_id         uuid not null references auth.users(id) on delete cascade,
  provider        text not null,               -- 'gemini'
  model           text not null,
  quality_score   int,
  vuln_class      text not null,               -- 'IDOR', 'SSRF', 'XSS-stored'...
  tech_tags       text[],
  summary         text not null,
  root_cause      text not null,
  attack_flow     jsonb not null,
  fix             jsonb not null,
  detection       jsonb,
  test_checklist  jsonb not null,
  unknowns        jsonb,                       -- raporda olmayan, tahmin edilen kısımlar
  lang            text default 'tr',
  is_shared       boolean default false,       -- ileride topluluk paylaşımı için
  created_at      timestamptz default now(),
  unique (writeup_id, user_id, lang)
);
create index on analyses (user_id, vuln_class);

create table user_llm_keys (
  user_id        uuid primary key references auth.users(id) on delete cascade,
  provider       text not null default 'gemini',
  encrypted_key  text not null,                -- Supabase Vault veya AES-256-GCM (aşağıya bak)
  key_last4      text not null,                -- UI'da maskeli gösterim: ****abcd
  triage_model   text not null,                -- model adları KODDA SABİT DEĞİL, burada
  analysis_model text not null,
  base_url       text,                         -- ileride OpenAI-uyumlu/Ollama için
  updated_at     timestamptz default now()
);

create table analysis_jobs (
  id          uuid primary key default gen_random_uuid(),
  user_id     uuid not null references auth.users(id) on delete cascade,
  writeup_id  uuid not null references writeups(id) on delete cascade,
  stage       text not null default 'queued',  -- queued | triage | analyzing | done | skipped | failed
  attempts    int not null default 0,
  error       text,
  run_after   timestamptz default now(),       -- 429 sonrası backoff için
  created_at  timestamptz default now()
);
```

**RLS:**
- `writeups`: giriş yapmış kullanıcı okuyabilir, yazma sadece service role ile.
- `analyses`, `analysis_jobs`: kullanıcı sadece `user_id = auth.uid()` olanları görür ve yazar.
- `user_llm_keys`: istemciden **hiç okunmaz**. Okuma/yazma sadece sunucu tarafında (service role). İstemciye sadece `key_last4`, provider ve model bilgisi döner (view veya RPC ile).

---

## 5. Güvenlik gereksinimleri (zorunlu)

- API key **şifreli** saklanır. Seçenekler: Supabase Vault veya sunucu env'indeki master key ile AES-256-GCM. Projeye uygun olanı seç ve gerekçesini yaz. Düz metin kolon yasak.
- Key **istemciye asla dönmez**. Tüm LLM çağrıları sunucu tarafında yapılır (Route Handler / Edge Function / worker).
- Key ve LLM istek gövdeleri **log'lanmaz**. Hata mesajlarında key maskelenir.
- Key kaydedilirken küçük bir test çağrısıyla doğrulanır.
- Kullanıcı key'ini silebilir. Silince ilgili şifreli veri tamamen kaldırılır.
- Gizlilik uyarısı: Gemini ücretsiz katmanında gönderilen içerik ürün geliştirmede kullanılabilir (**güncel şartları doğrula**). Public raporlar için sorun yok. İleride kullanıcının **kendi özel BountyTrack bulguları** analiz edilecekse UI'da açık uyarı gösterilmeli.

---

## 6. LLM katmanı

```ts
interface LLMProvider {
  generateJSON<T>(opts: {
    model: string;
    system: string;
    user: string;
    schema: object;          // JSON Schema (Gemini responseSchema'ya çevrilir)
  }): Promise<T>;
}
```

- **İlk adaptör: native Gemini API.** `responseMimeType: "application/json"` + `responseSchema` kullan. Native SDK/REST'te en temiz çalışan yol bu (**doğrula: güncel SDK ve parametre adları**).
- İleride: OpenAI-uyumlu adaptör (base URL ile OpenRouter / Ollama / Gemini'nin OpenAI-uyumlu endpoint'i). Yerel modeller şemaya daha az uyar, zod doğrulaması şart.
- Model adları **kodda sabit yazılmaz**. Kullanıcı ayarlarından (`user_llm_keys`) okunur, UI'da seçtirilir. Varsayılan öneri: triage = Flash serisi, analiz = Pro serisi.
- **Rate limit:** Ücretsiz katmanın dakikalık/günlük limitleri var. `analysis_jobs` kuyruğu sıralı işlenir, istekler arasında bekleme olur. 429 alınca exponential backoff ile `run_after` ileri alınır. Toplu analiz kuyruktan geçmeden doğrudan çağrı yapmaz.
- Her çıktı **zod** ile doğrulanır.

---

## 7. Prompt'lar

**Triage (ucuz model):**
```
Aşağıdaki bug bounty raporunu değerlendir. Yalnızca JSON döndür:
{ "quality_score": 0-10, "vuln_class": "...", "reason": "tek cümle" }
Puanlama: Teknik detay (istek/yanıt, payload, adımlar) yoksa ≤3.
Sansürlenmiş veya tek paragraflık raporlar ≤4.
```

**Deep analysis, system prompt:**
```
Sen bir purple team eğitmenisin. Okuyucu Türk bir bug bounty hunter.
Kurallar:
1. Yalnızca rapor metnindeki bilgiye dayan.
2. Metinde olmayan ama mantıksal olarak çıkardığın her şeyi "unknowns" alanına yaz,
   diğer alanlara karıştırma.
3. "root_cause" = geliştiricinin yaptığı yanlış varsayım. Zafiyetin adını tekrar etme.
4. Teknik terimleri İngilizce bırak (IDOR, payload, endpoint), açıklamaları Türkçe yaz.
5. Sadece verilen şemaya uyan JSON döndür.
```

**Çıktı şeması:**
```json
{
  "summary": "2-3 cümle",
  "root_cause": "string",
  "attack_flow": [{ "step": 1, "action": "string", "why_it_works": "string" }],
  "fix": { "wrong": "string", "right": "string", "code_hint": "string|null" },
  "detection": { "signals": ["string"], "where": "log | WAF | app monitoring" },
  "test_checklist": ["Kendi hedefinde ... kontrol et"],
  "tech_tags": ["string"],
  "unknowns": ["string"]
}
```

Prompt kalitesi en kritik iş. 20-30 gerçek raporla elle karşılaştırarak ayarla: model uyduruyor mu, `root_cause` gerçekten kök nedeni mi veriyor, yoksa zafiyet adını mı tekrar ediyor?

---

## 8. Arayüz

- `/learn`: rapor listesi (başlık, vuln_class rozeti, severity, bounty, tarih). Filtreler: bug sınıfı, teknoloji, "analiz edilmiş/edilmemiş". "Analiz et" butonu ve toplu analiz.
- `/learn/[id]`: özet → kök neden → adım adım saldırı (her adımda "neden çalışıyor") → yanlış/doğru düzeltme → tespit → checklist → **"Tahminler" kutusu** (`unknowns`, görsel olarak ayrı) → orijinal rapora link.
- `/settings/llm`: provider, key girişi (maskeli gösterim), triage/analiz modeli seçimi, key test ve silme, gizlilik uyarısı.
- `/showcase` (public, giriş gerektirmez): elle seçilmiş birkaç örnek analiz ve kayıt çağrısı.
- Key yoksa `/learn` liste görünür, "Analiz et" butonu ayarlara yönlendirir.

---

## 9. Hukuki / etik

- Write-up'lar yazarlarının içeriği. **Tam metin yeniden yayınlanmaz.** `raw_text` sadece analiz girdisi olarak tutulur, UI'da gösterilmez. Her zaman orijinal rapora link verilir.
- HackerOne verisi için **resmi API kullanılır** (scraping değil). **Kullanım şartlarını doğrula.**
- Sadece public/disclosed raporlar işlenir.

---

## 10. Yol haritası

| Hafta | İş |
|---|---|
| 1 | Migration'lar (4 tablo + RLS), H1 fetcher + dedupe + heuristik filtre, cron, `/settings/llm` + şifreli key saklama |
| 2 | `LLMProvider` + Gemini adaptörü, `analysis_jobs` worker'ı (rate limit/backoff), triage + deep analysis, zod, 20-30 raporla prompt ayarı |
| 3 | `/learn` ve `/learn/[id]` sayfaları, toplu analiz |
| 4 | `/showcase`, haftalık örüntü özeti ("bu hafta en çok çıkan sınıf ve ortak noktası"), ikinci kaynak (Medium RSS / Bugcrowd) |

**MVP dışı (sonra):** topluluk paylaşımı (`is_shared`), quiz, kullanıcının BountyTrack bulgularına göre öneri, dil seçimi, ek sağlayıcı adaptörleri.

---

## 11. Doğrulanacaklar (kod yazmadan önce)

1. **HackerOne Hacker API:** `GET /v1/hackers/hacktivity` için auth (API username + token, Basic Auth), query/filtre sözdizimi (disclosed filtresi), sayfalama, rate limit, yanıttaki alan adları.
2. **Rapor tam metni nasıl alınır?** Hacktivity yanıtı muhtemelen metadata döndürüyor. Disclosed raporun gövdesi için resmi/izinli yol hangisi? (Ör. `hackerone.com/reports/{id}.json` gibi public endpoint'ler var mı, ToS'a uygun mu?)
3. **Gemini API:** güncel model adları, `responseSchema` desteği ve kısıtları, ücretsiz katman limitleri ve veri kullanım şartları.
4. **Supabase Vault** ile kullanıcı başına secret saklamanın pratikliği, ya da AES-256-GCM alternatifi.
5. Edge Function timeout limitleri (worker için uygun mu?).
