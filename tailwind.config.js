/** @type {import('tailwindcss').Config} */
module.exports = {
    content: ["./websrc/**/*.{html,js,ts,tsx}"],
    theme: {
        fontFamily: {
            'mono': ['courier-new', 'courier', 'monospace'],
            'sans': ['Kanit'],

        },
    },
    future: {
        hoverOnlyWhenSupported: true,
    },
    plugins: [],
    theme: {
        extend: {
            container: {
                screens: {
                    sm: '100%',
                    md: '768px',
                    lg: '768px',
                    xl: '768px',
                    '2xl': '768px',
                },
            },
        },
    },
}