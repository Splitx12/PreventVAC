# PreventVAC
Software to prevent VAC from monitoring VAC-Protected games.

It achieves its goal by hooking different steamserver.dll and winapi functions to make the anticheat think there's been an error in return.

# Important
[vac_monitor_manager function](https://github.com/n00bes/PreventVAC/blob/73c71f5fd710cb99ecf93d82ae17af2b69e09c27/PreventVAC/init.cpp#L101) is very important and may cause unwanted side effect in lowering the trust factor because it **completely** prevents VAC from monitoring the game.

Why am I saying this?
Their server may be checking for callbacks done when registering a process monitor.
In the future, Valve may punish for this kind of action, the line should be commented if you notice bad decrease of trust factor.
