###1st) Try anonymous login

	rsync --list-only <target_ip>:: # lists directories available to anonymous login
	rsync --list-only <target_ip>::<available_directory>
	rsync <targe_ip>::<available_directory>/<file> <file> # download a file
