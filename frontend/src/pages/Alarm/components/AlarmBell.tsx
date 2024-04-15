import { PiBell } from 'react-icons/pi'
import { useNavigate } from 'react-router-dom'
const AlarmBell = () => {
	const navigate = useNavigate()
	return (
		<div>
			<PiBell
				className="font-bold"
				size={20}
				onClick={() => {
					navigate('/alarm')
				}}
			/>
		</div>
	)
}

export default AlarmBell
