import CircularProgress from '@mui/material/CircularProgress'
import { useState, useEffect } from 'react'
import axios from 'axios'
import SolveQuiz from './SolveQuiz'
import { useQuizStore } from './store'

interface IQuizData {
	correct: string
	dummy1: string
	dummy2: string
}

const Loading = ({ gptAnswer, capturedImage }: { gptAnswer: number; capturedImage: File }) => {
	const [quizData, setQuizData] = useState<IQuizData | undefined>()
	const { setAnswerType, setImage } = useQuizStore()

	const generateQuiz = (gptAnswer: number) => {
		axios
			.get(`${import.meta.env.VITE_BASE_URL}/problem`, { params: { number: gptAnswer } })
			.then((response) => {
				setQuizData(response.data.data)
				if (quizData?.correct === '음식물쓰레기') {
					setAnswerType(0)
				} else if (quizData?.correct === '일반쓰레기') {
					setAnswerType(1)
				} else {
					setAnswerType(2)
				}
			})
			.catch((error) => {
				console.error(error)
			})
	}

	useEffect(() => {
		setImage(capturedImage)
		generateQuiz(gptAnswer)
	}, [gptAnswer])

	return (
		<div className="pt-20">
			{quizData ? (
				<SolveQuiz quizData={quizData} capturedImage={capturedImage} />
			) : (
				<div>
					<div>
						<img src={URL.createObjectURL(capturedImage)} className="w-[60%] mx-[20%] mt-6 mb-10 rounded-2xl" />
					</div>
					<div className="text-white ml-5 text-lg font-semibold">
						<div>쓰레기를 판별 중이에요!</div>
						<div className="mb-5">잠시만 기다려주세요...</div>
						<div className="text-center">
							<CircularProgress />
						</div>
					</div>
				</div>
			)}
		</div>
	)
}

export default Loading
