import { useEffect, useState } from 'react'

const outerStyleClass = `absolute bg-[#ffffff4c] z-[1] opacity-0 rounded-full`
const innerStyleClass = `absolute bg-[#ffffff4c] z-0 opacity-0 rounded-full`

const Cloud = (blur: number, size: number) => {
	const [outerEffect, setOuterEffect] = useState(outerStyleClass)
	const [innerEffect, setInnerEffect] = useState(innerStyleClass)

	useEffect(() => {
		const timer = setTimeout(() => {
			setOuterEffect(outerEffect.replace('opacity-0', 'opacity-100') + ' transition-opacity duration-1000')
			setInnerEffect(innerEffect.replace('opacity-0', 'opacity-100') + ' transition-opacity duration-1000')
		}, 2000)
		return () => clearTimeout(timer)
	}, [])

	return (
		<>
			<div style={{ width: `${size}px`, height: `${size}px`, filter: `blur(${blur}px)` }} className={outerEffect}></div>
			<div
				style={{ width: `${size * 0.6}px`, height: `${size * 0.6}px`, filter: `blur(${blur}px)` }}
				className={innerEffect}
			></div>
		</>
	)
}

export default Cloud
