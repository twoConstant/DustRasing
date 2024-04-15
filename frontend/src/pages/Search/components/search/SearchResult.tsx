import { useEffect } from 'react'
import { RecentItemType, SearchResultProp } from '../../search-types'
import RecentItem from '../recent/RecentItem'
import { useInView } from 'react-intersection-observer'
import useInfiniteSearch from '../../api'

const SearchResult = ({ input, userUpdate }: SearchResultProp) => {
	const { ref: lastElementRef, inView: lastElementInView } = useInView()
	const { searchListData, fetchNextPage } = useInfiniteSearch(input)

	useEffect(() => {
		if (lastElementInView) {
			fetchNextPage()
		}
	}, [lastElementInView, searchListData, fetchNextPage])

	return (
		<ul className="flex flex-col px-4 pt-14 gap-8 z-10">
			{searchListData &&
				searchListData.map((user, index) => (
					<li key={user.userName} ref={index === searchListData.length - 1 ? lastElementRef : null}>
						<RecentItem type={RecentItemType.USER} userUpdate={userUpdate} userInfo={user} />
					</li>
				))}
		</ul>
	)
}

export default SearchResult
