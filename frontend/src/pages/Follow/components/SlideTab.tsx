import { useEffect, useState } from 'react'
import { motion } from 'framer-motion'
import { NavLink } from 'react-router-dom'
import { useRouter } from '../../../hooks/useRouter'
import { SlideTabProp } from '../../../components/interfaces'

const SlideTab = ({ tabInfo }: { tabInfo: SlideTabProp[] }) => {
	const [selectedIndex, setSelectedIndex] = useState<number>()
	const { currentPath } = useRouter()

	useEffect(() => {
		// bucket/write/{children}으로 안들어왔을 경우
		if (selectedIndex === undefined) {
			setSelectedIndex(0)
			return
		}
	}, [selectedIndex])

	useEffect(() => {
		tabInfo.forEach((item, index) => {
			if (currentPath.includes(item.path)) {
				setSelectedIndex(index)
			}
		})
	}, [currentPath])

	return (
		<div className="flex items-center justify-around z-10 fixed top-14 right-0 left-0 bg-background">
			<ul className={`flex gap-[2px] w-full`}>
				{tabInfo.map((tab, index) => {
					return (
						<li key={`hedaer-${index}`} className={`w-1/2 relative`}>
							<NavLink
								to={tab.path}
								// data-id={index}
								className={
									'inline-block w-full text-center py-2' +
									(selectedIndex === index ? ' text-textWhite font-[700]' : ' text-[#D9D9D9]   ')
								}
							>
								{tab.name}
							</NavLink>
							{selectedIndex === index && (
								<motion.div layoutId="underline" className="absolute h-[1px] bottom-0 w-full bg-white" />
							)}
						</li>
					)
				})}
			</ul>
		</div>
	)
}

export default SlideTab
