import { Link } from 'react-router-dom'

const AnswerOption = ({ wasteType, correct }: { wasteType: string; correct: string }) => {
	return (
		<div className="bg-gradient-to-tr from-purple-800/30 to-purple-400/30 flex justify-center items-center border-2 rounded-lg border-neutral-800/30 mr-5 mb-3 py-2 hover:bg-purple-500/30 transition-colors">
			{correct === wasteType ? (
				<Link to="correct" className="text-white font-semibold ">
					{wasteType}
				</Link>
			) : (
				<Link to="wrong" className="text-white font-semibold">
					{wasteType}
				</Link>
			)}
		</div>
	)
}

export default AnswerOption
