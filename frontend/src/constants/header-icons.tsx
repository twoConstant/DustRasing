import { IoChevronBackOutline } from 'react-icons/io5'
import { IoCloseOutline } from 'react-icons/io5'
import { IoMdMenu } from 'react-icons/io'
import { RiQrScanLine } from 'react-icons/ri'
import { IMenu } from '../components/interfaces'

export const icons: IMenu = {
	BACK: <IoChevronBackOutline size="2rem" className="text-poin1" />,
	HAMBERGER: <IoMdMenu size="2rem" className="text-poin1" />,
	CLOSE: <IoCloseOutline size="2rem" className="text-poin1" />,
	QRCODE: <RiQrScanLine size="2rem" className="text-poin1" />,
}
