/** @type {import('tailwindcss').Config} */
export default {
	content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
	theme: {
		extend: {
			colors: {
				whiteText: '#EAEAEA',
				GrayText: '#C4C4C4',
				background: '#111111',
			},
		},
	},
	plugins: [],
}
