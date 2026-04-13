/** Shared Framer Motion settings — subtle, consistent section reveals. */
export const easeSection = [0.22, 1, 0.36, 1] as const;

export const sectionViewport = { once: true, amount: 0.2 } as const;

export const sectionFadeUp = {
  initial: { opacity: 0, y: 22 },
  whileInView: { opacity: 1, y: 0 },
  viewport: sectionViewport,
  transition: { duration: 0.62, ease: easeSection },
};
