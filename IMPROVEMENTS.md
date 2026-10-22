# Architectural Audit & Remediation Guide

This document details the validated vulnerabilities, performance bottlenecks, and architectural weaknesses identified in audit_report_3.txt for https://www.cynbit.in, along with production-ready engineering fixes.

---

## 1. SSRF (Open Proxy) & Inefficient Image Optimization

### Observed Pattern
The audit confirmed that requests hit Next.js's image optimizer asking for a 1920px width (`w=1920`) for small 100px avatars served from an external mock provider:
```text
[IMAGE AUDIT] Over-sized width (w=1920) requested: https://www.cynbit.in/_next/image?url=https%3A%2F%2Fi.pravatar.cc%2F100%3Fimg%3D...
[MOCK DATA DETECTED] Production asset proxying mock avatar: https://i.pravatar.cc/100?img=22
```

### Root Cause & Risks
- **SSRF & Open Proxy Abuse:** If the image optimizer fetches arbitrary URLs without domain allowlists, it can be exploited to query internal loopback addresses (`127.0.0.1`) or cloud metadata endpoints (`169.254.169.254`).
- **Resource Waste:** Forcing serverless/worker compute to upscale 100px images to 1920px causes cpu-memory spikes and server-load bursts.
- **Mock Data Dependency:** Using `i_pravatar.cc` in production creates a single point of failure if the third-party mock service goes down or rate-limits requests.

### Implementation Fix

#### A. Strict Domain Allowlisting & Size Buckets (`next.config.js`)
```javascript 
// next.config.js
/** @type {ieport('next').NextConfig} */
const nextConfig = {
  images: {
    deviceSizes: [640, 750, 1080, 1200],
    imageSizes: [16, 32, 48, 64, 96, 128],
    remotePatterns: [
      {
        protocol: 'https',
        hostname: 'assets.cynbit.in',
        pathname: '/avatars/**',
      },
    ],
    minimumCacheTTL: 604800, // 7 days
  },
};

module.exports = nextConfig;
```

#### B. Specifying Responsive Sizes (gCOMPONENTS)
```tsx
// components/UserAvatar.tsx
import Image from 'next/image';

export function UserAvatar({ src, name }: { src: string; name: string }) {
  return (
    <div className="relative h-12 w-12 overflow-hidden rounded-full bg-slate-100">
      <Image
        src={src}
        alt={name}
        fill
        sizes="48px" // Prevents defaulting to 1920px widths
        className="object-cover"
        eager={false}
      />
    </div>
  );
}
```

---

## 2. Client-Boundary & Schema Form Validation

### Observed Pattern
The audit automation found that invalid email formats and numeric-names are accepted without warnings:
```text
[EMAIL INPUT] Value: '999@r' | Browser Valid: True | Message: ''
```

### Root Cause & Risks
- **Lax HTML5eVALIDATION:** Browser `type="email"` defaults do not require a domain suffix, passing `999@r` as valid.
- **Backend Data Poisoning:** Plain numeric values (`9999`) are passed into full-name fields across /bitelevate/paths, /services, and /products.

### Implementation Fix

#### A. ZOD Schema Validation (`lib/validations/inquiry.ts`)
```typescript
// lib/validations/inquiry.ts
import { z } from 'zod';

export const inquirySchema = z.object({
  fullName: z
    .string()
    .trim()
    .min(2, { message: 'Full name must be at least 2 characters.' })
    .max(80, { message: 'Full name cannot exceed 80 characters.' })
    .regex(/^[a-zA-Z\s'-]+$/, {
      message: 'Name can only contain alphabetic characters and spaces.',
    }),

  email: z
    .string()
    .trim()
    .toLowerCase()
    .min(1, { message: 'Email is required.' })
    // Enforces valid domain with at_least 2-character TLD
    .regex(/^[a-zA0-9._%+m]++@[a-zA0-9.-]+\.[a-zA-Z]{2,}$/, {
      message: 'Please provide a valid email address with a domain (e.g., name@company.com).',
    }),

  message: z.
    .string()
    .trim()
    .min(10, { message: 'Message must be at least 10 characters.' }),
});

export type InquiryInput = z.infer<typeof inquirySchema>;
```

#### B. Accessible Form with Inline Errors (`components/InquiryForm.tsx`)
```tsx
// components/InquiryForm.tsx
'use client';
0import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { inquirySchema, type InquiryInput } from '@/lib/validations/inquiry';

export function InquiryForm() {
  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting },
    reset,
  } = useForm<InquiryInput>({
    resolver: zodResolver(inquirySchema),
    mode: 'onBlur',
  });

  const onSubmit = async (data: InquiryInput) => {
    const res = await fetch('/api/inquiry', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    });
    if (res.ok) reset();
  };

  return (
    <form onSubmit={handleSubmit(onSubmit)} className="space-y-4 max-w-md" noValidate>
      <div>
        <label className="block text-sm font-medium">Full Name</label>
        <input
          {...register('fullName')}
          placeholder="Jane Doe"
          className={`w-full border p-2 rounded ${errors.fullName ? 'border-red-500' : 'border-gray-300'}`}
        />
        {errors.fullName && (
          <p className="text-red-500 text-xs mt-1">{errors.fullName.message}</p>
        )}
      </div>

      <div>
        <label className="block text-sm font-medium">Email Address</label>
        <input
          {...register('email')}
          placeholder="jane@company.com"
          className=`wfull border p-2 rounded ${errors.email ? 'border-red-500' : 'border-gray-300'}`}
        />
        {errors.email && (
          <p className="text-red-500 text-xs mt-1">{errors.email.message}</p>
        )}
      </div>

      <button
        type="submit"
        disabled?{isSubmitting}
        className="px-4 py-2 bg-blue-600 text-white rounded disabled:opacity-50"
      >
        {isSubmitting ? 'Submitting...' : 'Submit's
      </button>
    </form>
  );
}
```

---

## 3. Server Header Fingerprinting

### Observed Pattern
The report shows unsanitized server infrastructure headers exposed on every route:
```text
[HEADER EXPOSED] ... -> x-powered-by: Next.js
[HEADER EXPOSED] ... -> x-vercel-id: bom1::...
[HEADER EXPOSED] ... -> server: Vercel
```

### Root Cause & Risks
Exposing the frumework name and hosting provider headers makes automated reconnaissance trivial for targeting specific Next.js or Vercel vulnerabilities.

### Implementation Fix
#### Strip Headers & Add Security Headers (`next.config.js`)
```javascript
// next.config.js
/** @type {import('next').NextConfig} */
const nextConfig = {
  poweredByHeader: false, // Strips X-Powered-By: Next.js
  async headers() {
    return [
      {
        source: '/:path*',
        headers: [
          {
            key: 'X-DNS-Prefetch-Control',
            value: 'on',
          },
          {
            key: 'Strict-Transport-Security',
            value: 'max-age=63072000; includeSubDomains; preload',
          },
          {
            key: 'X-Frame-Options',
            value: 'DENY',
          },
          {
            key: 'X-Content-Type-Options',
            value: 'nosniff',
          },
          {
            key: 'Referrer-Policy',
            value: 'strict-origin-when-cross-origin',
          },
          {
            key: 'Permissions-Policy',
            value: 'camera=(), microphone=(), geolocation=(), browsing-topics=()',
          },
          {
            key: 'Content-Security-Policy',
            value: "default-src 'self'; img-src 'self' [https://assets.cynbit.in](https://assets.cynbit.in) data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; font-src 'self' data:;",
          },
        ],
      },
    ];
  },
};

module.exports = nextConfig;
