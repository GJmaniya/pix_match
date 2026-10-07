document.addEventListener('DOMContentLoaded', () => {
    // Select elements for animation
    const loginContainer = document.querySelector('.login-container');
    const leftPanel = document.querySelector('.left-panel');
    const rightPanel = document.querySelector('.right-panel');

    // GSAP Timeline for sequential animations
    const tl = gsap.timeline({ defaults: { ease: "power3.out" } });

    // Initial state: hide elements
    gsap.set([leftPanel, rightPanel], { autoAlpha: 0 });

    // 1. Animate the main login container to fade in and slide up
    tl.fromTo(loginContainer, 
        { autoAlpha: 0, y: 50, scale: 0.95 }, 
        { autoAlpha: 1, y: 0, scale: 1, duration: 1.2, delay: 0.2, ease: "power3.out" }
    );

    // 2. Animate elements within the left panel
    tl.fromTo(leftPanel,
        { autoAlpha: 0, x: -30 },
        { autoAlpha: 1, x: 0, duration: 0.8 },
        "<0.3" // Start 0.3 seconds after the previous animation ends
    );
    tl.fromTo(leftPanel.querySelector('.logo'), 
        { autoAlpha: 0, y: -20 }, 
        { autoAlpha: 1, y: 0, duration: 0.6 },
        "<0.2"
    );
    tl.fromTo(leftPanel.querySelector('.illustration'), 
        { autoAlpha: 0, scale: 0.8 }, 
        { autoAlpha: 1, scale: 1, duration: 0.7, ease: "back.out(1.7)" },
        "<0.2"
    );
    tl.fromTo(leftPanel.querySelector('h1'), 
        { autoAlpha: 0, x: -20 }, 
        { autoAlpha: 1, x: 0, duration: 0.6 },
        "<0.2"
    );
    tl.fromTo(leftPanel.querySelector('p'), 
        { autoAlpha: 0, x: -20 }, 
        { autoAlpha: 1, x: 0, duration: 0.6 },
        "<0.1"
    );

    // 3. Animate elements within the right panel
    tl.fromTo(rightPanel,
        { autoAlpha: 0, x: 30 },
        { autoAlpha: 1, x: 0, duration: 0.8 },
        "<0.3" // Start 0.3 seconds after the leftPanel animation starts
    );
    tl.fromTo(rightPanel.querySelector('.form-title'), 
        { autoAlpha: 0, y: -20 }, 
        { autoAlpha: 1, y: 0, duration: 0.6 },
        "<0.2"
    );
    tl.fromTo(rightPanel.querySelector('.google-signin'), 
        { autoAlpha: 0, y: 20 }, 
        { autoAlpha: 1, y: 0, duration: 0.6 },
        "<0.1"
    );
    tl.fromTo(rightPanel.querySelector('.separator'), 
        { autoAlpha: 0, scaleX: 0 }, 
        { autoAlpha: 1, scaleX: 1, duration: 0.5, transformOrigin: "center" },
        "<0.1"
    );
    tl.fromTo(rightPanel.querySelector('.form-subtitle'), 
        { autoAlpha: 0, y: 20 }, 
        { autoAlpha: 1, y: 0, duration: 0.6 },
        "<0.1"
    );
    tl.fromTo(rightPanel.querySelectorAll('.input-group'), 
        { autoAlpha: 0, y: 20 }, 
        { autoAlpha: 1, y: 0, duration: 0.6, stagger: 0.15 }, // Stagger multiple input groups
        "<0.1"
    );
    tl.fromTo(rightPanel.querySelector('.login-button'), 
        { autoAlpha: 0, scale: 0.8 }, 
        { autoAlpha: 1, scale: 1, duration: 0.7, ease: "back.out(1.7)" },
        "<0.2"
    );

    // Optional: Add hover animations for buttons
    gsap.utils.toArray('.google-signin, .login-button').forEach(button => {
        button.addEventListener('mouseenter', () => {
            gsap.to(button, { scale: 1.03, duration: 0.3, ease: "power1.out" });
        });
        button.addEventListener('mouseleave', () => {
            gsap.to(button, { scale: 1, duration: 0.3, ease: "power1.out" });
        });
    });
});