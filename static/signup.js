document.addEventListener('DOMContentLoaded', () => {

    // Set initial states for animation (elements are invisible)
    gsap.set(".info-panel", { x: -100, opacity: 0 });
    gsap.set(".form-panel", { x: 100, opacity: 0 });
    gsap.set(".form-panel h1, .google-btn, .divider, .email-login-p, .form-group, .submit-btn", { 
        y: 30, 
        opacity: 0 
    });

    // Create a timeline for a controlled sequence
    const tl = gsap.timeline({ defaults: { ease: "power2.out" } });

    // Animation sequence
    tl.to(".info-panel", { 
        x: 0, 
        opacity: 1, 
        duration: 0.8 
    })
    .to(".form-panel", { 
        x: 0, 
        opacity: 1, 
        duration: 0.8 
    }, "-=0.5") // Overlap animation for smoother transition
    .to(".form-panel h1, .google-btn, .divider, .email-login-p, .form-group, .submit-btn", {
        y: 0,
        opacity: 1,
        duration: 0.6,
        stagger: 0.08 // Stagger the animation of each form element
    }, "-=0.3");

});