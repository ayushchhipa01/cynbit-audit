# Cynbit Web Architecture & Security Audit

Automated passive client-side security, API behavior, and performance audit for `https://www.cynbit.in`.

---

## 🛠️ Setup & Running the Audit

1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   playwright install chromium
   ```

2. Run the audit script:
   ```bash
   python audit_script.py
   ```
   The script generates `audit_report.txt` containing real-time network logs and form boundary test results.

---

## 🔍 Key Findings

* **SSRF / Open Proxy & Image Sizing Risk**: The image optimization endpoint was observed scaling low-resolution avatars (e.g., from `i.pravatar.cc`) up to `1920px` (`w=1920`).
* **Input Validation Gaps**: Form inputs accepted invalid email patterns (such as `999@r`) without enforcing domain structure, and numeric strings (`9999`) were accepted into name fields.
* **Header Information Exposure**: Framework and deployment headers (`x-powered-by`, `x-vercel-id`, `server`) were exposed in response streams.
* **Aggressive RSC Prefetching**: Route links in viewports triggered eager React Server Component (`_rsc`) payload downloads across multiple routes simultaneously.

---

## 💡 Recommended Fixes & Architecture Snippets

### 1. Hardening Image Optimization (`next.config.js`)
Constrain resizing dimensions and restrict allowed remote hosts to self-hosted assets:

```javascript
/** @type {import('next').NextConfig} */
const nextConfig = {
  images: {
    deviceSizes: [640, 750, 828, 1080, 1200],
    imageSizes: [16, 32, 48, 64, 96, 128, 256],
    remotePatterns: [
      {
        protocol: 'https',
        hostname: 'assets.cynbit.in',
        pathname: '/avatars/**',
      },
    ],
  },
};
module.exports = nextConfig;
```

### 2. Schema Validation (Zod + React Hook Form)
Enforce strict email domain verification and character restrictions:

```typescript
import { z } from 'zod';

export const InquirySchema = z.object({
  fullName: z.string().trim().min(2).regex(/^[a-zA-Z\s'-]+$/),
  email: z.string().trim().toLowerCase().regex(/^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/),
  message: z.string().trim().min(10),
});
```

### 3. Server Header Disablement (`next.config.js`)
Disable framework headers and add security headers:

```javascript
module.exports = {
  poweredByHeader: false,
};
```