import { IoMdClose } from 'react-icons/io'
import RecentItem from './RecentItem'
import { RecentItemType, RecentSearchProp } from '../../search-types'

/*
  최근 검색은 최근 검색어, 최근 본 유저 순으로 표시된다.
  localStorage에 각각 저장해두고 검색어와 유저 각 순서대로 표시하기
*/

const RecentSearch = ({ userUpdate, recentKeywords, recentUsers, handleDelete }: RecentSearchProp) => {
	return (
		<div className="flex flex-col pt-12">
			<h3 className="text-base">최근 검색</h3>
			{/* 최근 기록 KEYWORD */}
			{!recentKeywords.length && !recentUsers.length ? (
				<p className="w-full text-center py-4 text-GrayText">검색 이력이 없습니다.</p>
			) : (
				<>
					<ul className="flex flex-col pl-3 pt-2">
						{recentKeywords.map((keyword) => (
							<li key={keyword.id} className="flex items-center gap-3 justify-between py-2">
								<RecentItem type={RecentItemType.KEYWORD} userUpdate={userUpdate} keyword={keyword} />
								<IoMdClose
									onClick={() => handleDelete(RecentItemType.KEYWORD, keyword.id)}
									className="w-2/12 size-5 text-GrayText"
								/>
							</li>
						))}
					</ul>

					{/* 최근 기록 KEYWORD */}
					<ul className="flex flex-col pl-3">
						{recentUsers.map((user, index) => (
							<li key={`${user.profileImg}${index}`} className="flex items-center gap-3 justify-between py-2">
								<RecentItem type={RecentItemType.USER} userUpdate={userUpdate} userInfo={user} />
								<IoMdClose
									onClick={() => handleDelete(RecentItemType.USER, user.id)}
									className="w-2/12 size-5 text-GrayText"
								/>
							</li>
						))}
					</ul>
				</>
			)}
		</div>
	)
}

export default RecentSearch
