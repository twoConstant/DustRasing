import ResultModal from './components/ResultModal'
import { useState } from 'react'
import DetailedInst from './components/DetailedInst'

const WrongPage = () => {
	const comment = '땡! 아쉬워요..'
	const emoji = 'SadEmoji'
	const result = ''
	const next = '재도전하기'
	const [isVisible, setIsvisible] = useState(true)

	const handleVisibility = () => {
		setIsvisible(false)
	}

	return (
		<div>
			{isVisible ? (
				<div className="w-full h-full">
					<div className="bg-black bg-opacity-90 absolute z-10 w-full h-[110%]" onClick={handleVisibility}></div>
					<ResultModal comment={comment} emoji={emoji} result={result} next={next} />
				</div>
			) : null}
			<DetailedInst />
		</div>
	)
}

export default WrongPage
