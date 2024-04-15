import { IoSearch } from 'react-icons/io5'
import { RecentItemType, SearchItemProp } from '../../search-types'
import { useRouter } from '../../../../hooks/useRouter'

const RecentItem = ({ userUpdate, type, keyword, userInfo }: SearchItemProp) => {
	const { routeTo } = useRouter()
	const handleClick = () => {
		userUpdate!(type, userInfo, keyword)
		if (type === RecentItemType.USER && userInfo) {
			routeTo(`/invitor/${userInfo?.id}`)
		}
	}

	return (
		<div onClick={handleClick} className="flex items-center gap-4 h-[44px] w-full">
			<div className="w-2/12 rounded-full overflow-hidden">
				{type === RecentItemType.KEYWORD ? (
					<IoSearch className="w-full size-6" />
				) : (
					userInfo && (
						<img
							src={userInfo.profileImg ? userInfo.profileImg : `/public/dummy/random/${userInfo.id % 7}.jpeg`}
							alt="dummy"
							className="object-cover aspect-square"
						/>
					)
				)}
			</div>
			<div className="w-10/12">
				{type === RecentItemType.KEYWORD
					? keyword!.text
					: userInfo && (
							<div className="flex flex-col justify-start">
								<p className="text-whiteText">{userInfo.userName}</p>
								<p className="text-xs text-GrayText">Lv.{userInfo.level}</p>
							</div>
					  )}
			</div>
		</div>
	)
}

export default RecentItem
