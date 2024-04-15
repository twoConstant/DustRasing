import Header from '../../components/Header'
import { IMenu, IMenuFunc } from '../../components/interfaces'
import { icons } from '../../constants/header-icons'
import { useNavigate } from 'react-router-dom'
import AnswerOption from './components/AnswerOption'
import { useEffect, useState } from 'react'

interface IQuizData {
	correct: string
	dummy1: string
	dummy2: string
}

const SolveQuiz = ({ quizData, capturedImage }: { quizData: IQuizData; capturedImage: File }) => {
	const navigate = useNavigate()
	const menu: IMenu = { left: icons.BACK, center: '퀴즈', right: undefined }
	const func: IMenuFunc = { left_func: () => navigate('/'), right_func: undefined }

	const options: string[] = Object.values(quizData)
	const [shuffledArr, setShuffledArr] = useState<string[]>()
	useEffect(() => {
		const shuffled = options.sort(() => Math.random() - 0.5)
		setShuffledArr(shuffled)
	}, [])

	return (
		<div>
			<Header menu={menu} func={func}></Header>
			<img src={URL.createObjectURL(capturedImage)} alt="" className="w-[60%] mx-[20%] mt-6 mb-10 rounded-2xl" />
			<div className="">
				<div className="text-white text-lg font-semibold my-5 ml-5">
					<div>이 물건은 어떤 쓰레기로</div>
					<div>분류할까요</div>
				</div>
				<div className="ml-5">
					{shuffledArr &&
						shuffledArr.length > 0 &&
						shuffledArr.map((option) => <AnswerOption wasteType={option} correct={quizData.correct} key={option} />)}
				</div>
			</div>
		</div>
	)
}

export default SolveQuiz
