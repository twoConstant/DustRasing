import { useNavigate } from 'react-router-dom'
import { useState } from 'react'
import Header from '../../components/Header'
import { IMenu, IMenuFunc } from '../../components/interfaces'
import { icons } from '../../constants/header-icons'
import HowToUse from './components/HowToUse'
import axios from 'axios'
import Loading from './Loading'

const Quiz = () => {
	const [base64Image, setBase64Image] = useState<string | ArrayBuffer | null>(null)
	const [capturedImage, setCapturedImage] = useState<File | undefined>()
	const [isLoading, setIsLoading] = useState(false)
	const [gptAnswer, setGptAnswer] = useState<number>(-1)
	const handleCaptureImage = async (e: React.ChangeEvent<HTMLInputElement>) => {
		const preview = e.target.files?.[0]
		setCapturedImage(preview)
		const file = e.target.files && (await parseFile(e.target.files[0]))
		setBase64Image(file as string | ArrayBuffer | null)
	}

	const processFile = (currentFile: File) => {
		return new Promise((resolve) => {
			const reader = new FileReader()
			reader.readAsDataURL(currentFile)
			reader.onload = () => {
				const result = reader.result
				resolve(result)
			}
		})
	}

	const parseFile = async (currentFile: File) => {
		const parsedFile = await processFile(currentFile)
		return parsedFile
	}

	const headers = {
		'Content-Type': 'application/json',
		Authorization: `Bearer ${import.meta.env.VITE_OPENAI_API_KEY}`,
	}

	const payload = {
		model: 'gpt-4-vision-preview',
		messages: [
			{
				role: 'user',
				content: [
					{
						type: 'text',
						text: 'please identify what kind of garbage it would be, possibly in the future as well. there are 7 types of answer you can offer. first, if it mostly contains plastic, answer "4". answer "6", if it mostly are made of paper. answer "3" if it is a aluminium can. answer "5" if it is glass. answer "1" if it could be food waste. answer "2" if you cannot figure out what type of waste they are, or if it is general waste. answer "0" this is really important by the way, if they are human or animals. give the answer only as a number. simply a number. ',
					},
					{
						type: 'image_url',
						image_url: {
							url: base64Image,
							detail: 'high',
						},
					},
				],
			},
		],
		max_tokens: 300,
	}

	const navigate = useNavigate()

	const handleAskGPT = () => {
		setIsLoading(true)
		axios
			.post('https://api.openai.com/v1/chat/completions', payload, { headers })
			.then((response) => {
				const answer = response.data.choices[0].message.content
				setGptAnswer(answer)
				if (answer === '0') {
					setGptAnswer(-1)
					window.alert('쓰레기로 분류할 수 없습니다. 다시 촬영해주세요.')
					window.location.reload()
				}
			})
			.catch((error) => {
				console.error('Error:', error)
			})
	}

	const menu: IMenu = { left: icons.BACK, center: '퀴즈', right: undefined }
	const func: IMenuFunc = { left_func: () => navigate('/'), right_func: undefined }
	return (
		<div>
			<Header menu={menu} func={func}></Header>
			{isLoading && capturedImage ? (
				<Loading gptAnswer={gptAnswer} capturedImage={capturedImage} />
			) : (
				<div>
					<div className="pt-20 flex flex-col items-center justify-center ">
						{capturedImage ? (
							<img src={URL.createObjectURL(capturedImage)} className="w-[60%] mx-[20%] mt-6 mb-10 rounded-2xl" />
						) : (
							<div>
								<HowToUse />
							</div>
						)}
					</div>
					{capturedImage ? (
						<div className="flex justify-center">
							<label htmlFor="camera">
								<div className="text-white font-semibold text-lg bg-purple-800 rounded-full px-6 py-2 leading-9 hover:bg-purple-500 transition-colors mb-4 mr-3">
									다시 찍기
								</div>
							</label>
							<div
								onClick={handleAskGPT}
								className="text-white font-semibold text-lg bg-purple-800 rounded-full px-6 py-2 leading-9 hover:bg-purple-500 transition-colors mb-4"
							>
								제출하고 퀴즈 풀기
							</div>
						</div>
					) : (
						<label htmlFor="camera" className="flex justify-center">
							<div className="text-white font-semibold text-lg bg-purple-800 rounded-full px-6 py-2 leading-9 hover:bg-purple-500 transition-colors mb-4 ">
								사진 찍고 퀴즈 풀어보기
							</div>
						</label>
					)}
					<input
						id="camera"
						type="file"
						accept="image/*"
						capture="environment"
						onChange={handleCaptureImage}
						className="hidden"
					/>
				</div>
			)}
		</div>
	)
}

export default Quiz
