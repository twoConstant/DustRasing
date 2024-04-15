import ResultModal from './components/ResultModal'
import DetailedInst from './components/DetailedInst'
import { useState, useEffect } from 'react'
import axios from 'axios'

const CorrectPage = () => {
	const comment = '정답입니다!'
	const emoji = 'DropletEmoji'
	const result = '물 1개 획득'
	const next = '물 주러 가기'
	const [isVisible, setIsvisible] = useState(true)

	const handleVisibility = () => {
		setIsvisible(false)
	}

	const token = localStorage.getItem('token')
	useEffect(() => {
		axios
			.put(`${import.meta.env.VITE_API_BASE_URL}/problem`, {}, { headers: { Authorization: `Bearer ${token}` } })
			.then((response) => {
				console.log(response.data)
			})
			.catch((error: unknown) => {
				console.error('Error', error)
			})
	}, [])

	return (
		<div className="">
			{isVisible ? (
				<div className="w-full h-full">
					<div className="bg-black bg-opacity-90 absolute z-10 w-full h-[110%]" onClick={handleVisibility}></div>
					<ResultModal comment={comment} emoji={emoji} next={next} result={result} />
				</div>
			) : null}

			<DetailedInst />
		</div>
	)
}

export default CorrectPage
