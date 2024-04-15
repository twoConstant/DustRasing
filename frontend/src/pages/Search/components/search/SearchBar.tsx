import { MdCancel } from 'react-icons/md'
import { IoSearch } from 'react-icons/io5'
import { searchProp } from '../../search-types'

const SearchBar = ({ input, setInput, setIsFocused, handleInput, handleEnter }: searchProp) => {
	const handleCancel = () => {
		setInput('')
	}

	return (
		<div className="flex gap-2 items-center text-whiteText fixed top-14 right-0 left-0 px-4 bg-background pb-4">
			<div className="flex items-center justify-between px-3 py-2 w-[90%] shrink-0 bg-neutral-800 rounded-lg">
				<div className="flex gap-2 w-full">
					<IoSearch className="size-6" />
					<input
						type="text"
						value={input}
						onFocus={() => setIsFocused(true)}
						onBlur={() => setIsFocused(false)}
						placeholder="사용자를 검색해 보세요."
						onKeyDown={handleEnter}
						onChange={handleInput}
						className="bg-neutral-800 focus:outline-none w-full"
					/>
				</div>
				<MdCancel onClick={handleCancel} className="size-5" />
			</div>
			<p onClick={handleCancel} className="w-full text-center">
				취소
			</p>
		</div>
	)
}

export default SearchBar
