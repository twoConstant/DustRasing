import { IHeaderProp } from './interfaces'
const Header = (props: IHeaderProp) => {
	const { left, center, right } = props.menu
	const { left_func, right_func } = props.func

	return (
		<div className="fixed text-whiteText top-0 z-10 flex items-center justify-between w-full max-w-screen-sm h-14 px-5 bg-background">
			{left ? <div onClick={left_func}>{left}</div> : <div className="invisible">{right}</div>}
			<div className="text-lg font-bold">{center}</div>
			{right ? <div onClick={right_func}>{right}</div> : <div className="invisible">{left}</div>}
		</div>
	)
}

export default Header
