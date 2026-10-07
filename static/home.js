document.addEventListener('DOMContentLoaded', () => {
    // GSAP Animations
    gsap.from('.logo', { opacity: 0, duration: 1, delay: 0.5, y: -50 });
    gsap.from('.nav-links li', { opacity: 0, duration: 1, delay: 1, y: -50, stagger: 0.2 });
    gsap.from('.nav-actions', { opacity: 0, duration: 1, delay: 1.5, y: -50 });

    gsap.from('.hero-content h1', { opacity: 0, duration: 1, delay: 2, y: 100 });
    gsap.from('.hero-content p', { opacity: 0, duration: 1, delay: 2.5, y: 50 });
    gsap.from('.features .feature-card', { opacity: 0, duration: 1, delay: 3, y: 50, stagger: 0.3 });
    gsap.from('.benefits span', { opacity: 0, duration: 1, delay: 3.5, x: -50, stagger: 0.2 });
    gsap.from('.btn-primary.btn-large', { opacity: 0, duration: 1, delay: 4, scale: 0.5 });
});
