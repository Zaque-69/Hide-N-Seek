rule WinlockerVB6Blacksod {
	meta : 
		author = "Z4que - All rights reserved"
		date = "14/12/2024"

	strings:
		$header = { 4D 5A }

		// Software\Caphyon\Advanced Installer\
		$a1 = { 53 6F 66 74 77 61 72 65 5C 43 61 70 68 79 6F 6E 5C 41 64 76 61 6E 63 65 64 20 49 6E 73 74 61 6C 6C 65 72 5C }

		// SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\
		$a2 = { 53 4F 46 54 57 41 52 45 5C 4D 69 63 72 6F 73 6F 66 74 5C 57 69 6E 64 6F 77 73 5C 43 75 72 72 65 6E 74 56 65 72 73 69 6F 6E 5C 55 6E 69 6E 73 74 61 6C 6C 5C }

		// DrawThemeBackground
		$a3 = { 44 72 61 77 54 68 65 6D 65 42 61 63 6B 67 72 6F 75 6E 64 }

		// S.y.s.H.e.a.d.e.r.3.2
		$a4 = { 53 00 79 00 73 00 48 00 65 00 61 00 64 00 65 00 72 00 33 00 32 }

		// \.u.s.e.r.s.\.v.i.c.t.o.r.\.d.e.s.k.t.o.p.
		$a5 = { 5C 00 75 00 73 00 65 00 72 00 73 00 5C 00 76 00 69 00 63 00 74 00 6F 00 72 00 5C 00 64 00 65 00 73 00 6B 00 74 00 6F 00 70 00 }

		// \.b.r.a.n.c.h.\.e.x.t.e.r.n.a.l.u.i.\.c.o.n.t.r.o.l.s.\.g.e.n.e.r.i.c./.V.i.s.u.a.l.S.t.y.l.e.B.o.r.d.e.r
		$a6 = { 5C 00 62 00 72 00 61 00 6E 00 63 00 68 00 5C 00 65 00 78 00 74 00 65 00 72 00 6E 00 61 00 6C 00 75 00 69 00 5C 00 63 00 6F 00 6E 00 74 00 72 00 6F 00 6C 00 73 00 5C 00 67 00 65 00 6E 00 65 00 72 00 69 00 63 00 2F 00 56 00 69 00 73 00 75 00 61 00 6C 00 53 00 74 00 79 00 6C 00 65 00 42 00 6F 00 72 00 64 00 65 00 72 }

		// @echo off ATTRIB -r "%s"
		$a7 = { 40 65 63 68 6F 20 6F 66 66 20 0D 0A 41 54 54 52 49 42 20 2D 72 20 22 25 73 22 }

		// try rd "%s" if exist "%s" goto try ATTRIB -r "%s" del "%s" | cls...@echo of
		$a8 = { 74 72 79 20 0D 0A 72 64 20 22 25 73 22 20 0D 0A 69 66 20 65 78 69 73 74 20 22 25 73 22 20 67 6F 74 6F 20 74 72 79 0D 0A 41 54 54 52 49 42 20 2D 72 20 22 25 73 22 20 0D 0A 64 65 6C 20 22 25 73 22 20 7C 20 63 6C 73 00 00 00 40 65 63 68 6F 20 6F 66 }

		// C.:.\.F.A.K.E._.D.I.R
		$a9 = { 43 00 3A 00 5C 00 46 00 41 00 4B 00 45 00 5F 00 44 00 49 00 52 }

		// U.S.E.R.P.R.O.F.I.L.E
		$a10 = { 55 00 53 00 45 00 52 00 50 00 52 00 4F 00 46 00 49 00 4C 00 45 }

		// Copyright (c) 1992-2004 by P.J. Plauger, licensed by Dinkumware, Ltd. ALL RIGHTS RESERVED
		$a11 = { 43 6F 70 79 72 69 67 68 74 20 28 63 29 20 31 39 39 32 2D 32 30 30 34 20 62 79 20 50 2E 4A 2E 20 50 6C 61 75 67 65 72 2C 20 6C 69 63 65 6E 73 65 64 20 62 79 20 44 69 6E 6B 75 6D 77 61 72 65 2C 20 4C 74 64 2E 20 41 4C 4C 20 52 49 47 48 54 53 20 52 45 53 45 52 56 45 44 }

	condition : 
		$header at 0 
		and 9 of ($a*)
		and filesize < 3MB
}