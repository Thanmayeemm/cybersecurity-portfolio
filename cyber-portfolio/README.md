# Cyber Portfolio — Next.js + Tailwind

A dark, recruiter-friendly cybersecurity portfolio: hero, about, featured SOAR project, skills, and contact.

## Prerequisites

- Node.js **18+** (LTS recommended)
- npm, pnpm, or yarn

## Run locally

```bash
cd cyber-portfolio
npm install
npm run dev
```

Open [http://localhost:3000](http://localhost:3000).

### Customize content

Edit **`lib/site-config.ts`**:

- Name, title, intro, about text  
- Email, LinkedIn, GitHub URLs  
- **`soarProjectUrl`** — link to your SOAR repo on GitHub  

## Build for production

```bash
npm run build
npm start
```

## Deploy

### Vercel (recommended)

1. Push this folder to a GitHub repository.
2. Go to [vercel.com](https://vercel.com) → **Add New Project** → import the repo.
3. Root directory: `cyber-portfolio` (if the repo contains multiple projects) or leave default if this is the repo root.
4. Deploy — Next.js is detected automatically.

### Netlify

1. **Build command:** `npm run build`  
2. **Publish directory:** `.next` is not static export by default — use **Netlify Next.js plugin** or run on **Vercel**.

For Netlify with Next 14, use the official [Netlify Next adapter](https://docs.netlify.com/frameworks/next-js/overview/) or deploy via **Vercel**.

### Static export (optional)

This app uses the App Router and client components; for a fully static site you would add `output: 'export'` in `next.config.mjs` and avoid server-only features. The default setup targets **Node** hosting (Vercel, Railway, etc.).

## Tech stack

- [Next.js 14](https://nextjs.org/) (App Router)
- [Tailwind CSS](https://tailwindcss.com/)
- [Framer Motion](https://www.framer.com/motion/) (animations)

## Project structure

```
cyber-portfolio/
├── app/
│   ├── globals.css
│   ├── layout.tsx
│   └── page.tsx
├── components/
│   ├── About.tsx
│   ├── Contact.tsx
│   ├── Footer.tsx
│   ├── Hero.tsx
│   ├── Navbar.tsx
│   ├── Projects.tsx
│   └── Skills.tsx
├── lib/
│   └── site-config.ts
├── package.json
├── tailwind.config.ts
└── tsconfig.json
```

---

Built for portfolio and interview demos. Update `site-config.ts` before publishing.
