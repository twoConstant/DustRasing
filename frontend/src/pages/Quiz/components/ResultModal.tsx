import { useNavigate } from 'react-router-dom'
import { DropletEmoji, SadEmoji } from '../../../components/Emojis'
interface IProps {
	comment: string
	emoji: string
	result: string
	next: string
}

const ResultModal = (props: IProps) => {
	const navigate = useNavigate()
	const handleNextStep = () => {
		if (props.next === '재도전하기') {
			window.history.back()
		} else if (props.next === '물 주러 가기') {
			navigate('/')
		}
	}
	return (
		<div className="">
			<div className="flex flex-col items-center bg-stone-800 absolute z-20 rounded-xl py-5 left-[16%] top-[35%] w-[68%]">
				<div className="text-white mb-5">{props.comment}</div>
				{props.emoji === 'SadEmoji' ? <SadEmoji /> : <DropletEmoji />}
				<div className="text-white font-semibold mt-1">{props.result}</div>
				<div
					onClick={handleNextStep}
					className="text-white font-semibold bg-purple-800 rounded-full px-4 leading-9 hover:bg-purple-500 transition-colors mt-3"
				>
					{props.next}
				</div>
			</div>
		</div>
	)
}

export default ResultModal
