import throwing from '../assets/throwing.png'

const HowToUse = () => {
	return (
		<div className="flex flex-col items-center">
			<header className="text-white flex flex-col items-center font-bold text-lg">
				<div>쓰레기를 버리는 방법이 궁금하다면?</div>
				<div>카메라에 비추어 확인해보세요</div>
			</header>
			<img src={throwing} alt="" className="h-[460px] my-4" />
		</div>
	)
}

export default HowToUse
