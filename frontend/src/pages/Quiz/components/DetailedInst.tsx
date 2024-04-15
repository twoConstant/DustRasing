import { useNavigate } from 'react-router-dom'
import { useQuizStore } from '../store'
import Header from '../../../components/Header'
import { IMenu, IMenuFunc } from '../../../components/interfaces'
import { icons } from '../../../constants/header-icons'

const DetailedInst = () => {
	const menu: IMenu = { left: icons.BACK, center: '퀴즈', right: undefined }
	const func: IMenuFunc = { left_func: () => navigate('/'), right_func: undefined }
	const wasteData = [
		{ name: '음식물쓰레기', container: '음식물쓰레기 수거함', days: '화, 목, 일' },
		{
			name: '일반쓰레기',
			container: '종량제 봉투',
			days: '월~금',
		},
		{
			name: '재활용쓰레기',
			container: '투명한 비닐',
			days: '월~금',
		},
	]
	const { answerType, image } = useQuizStore()
	const navigate = useNavigate()
	const handleMoreQuiz = () => {
		navigate('/quiz')
	}
	return (
		<div className="text-white">
			<Header menu={menu} func={func}></Header>
			<div className="pt-16 flex flex-col items-center">
				{image && <img src={URL.createObjectURL(image)} alt="" className="w-[60%] mx-[20%] mt-6 mb-10 rounded-2xl" />}
				<div className="text-lg bg-stone-800 mx-6 p-8 rounded-xl my-5">
					<div className="mb-7">
						이 물건은 <span className="font-semibold">{wasteData[answerType].name}</span>로 배출해요
					</div>
					<div>
						<span className="font-semibold">{wasteData[answerType].container}</span>에 넣어서
					</div>
					<div>
						<span className="font-semibold">{wasteData[answerType].days}요일</span> 해가 진 후에
					</div>
					<div>내 집 앞에 배출해주세요</div>
				</div>
				<div
					onClick={handleMoreQuiz}
					className="text-white font-semibold bg-purple-800 rounded-full px-4 leading-9 hover:bg-purple-500 transition-colors mb-4 mr-3 flex justify-center w-fit p-1"
				>
					+ 퀴즈 더 풀기
				</div>
			</div>
		</div>
	)
}

export default DetailedInst
