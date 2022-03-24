# DexoFriend

#### DexoFriend is a free, open source Discord bot for managing whitelists populated with Cardano addresses. DexoFriend can:
- Set up a whitelist with opening and closing times.
- Accept mainnet addresses, stake addresses, and ADA handles.
- Restrict whitelisting to a specific channel.
- Provide you with up-to-date statistics about your whitelist.
- Allow mods to manually add/remove/check the whitelist entries of their users.
- Verify user wallets and assign roles to holders of specific policy IDs.
- Export the entire whitelist to a JSON file.
- Query stake addresses on the fly (e.g. from a minter) using our REST API.
## 1. Permissions
- While all commands are visible to all users on your server, these mod commands are only usable by users with the "edit channels" permission.
- This is because access to DexoFriend whitelists are controlled by channel access and not role access. More details below in the "Whitelist Access" section.
- The motivation here is that you might want to restrict slash command usage to a certain channel, as opposed to letting users with a specific role whitelist in whatever channel they want.
- Unauthorized users who try to run the mod commands will get an error.
- Mods can always access the whitelist regardless of whether or not it is open or closed.
## 2. API Access
- DexoFriend provides a REST API which allows minting devs to access the whitelist in realtime via their minting server.
- This allows for a whitelist to remain open during a minting period, such that users can update their addresses white minting is active.
- Another use case is to use DexoFriend not for a pre-mint whitelist, but simply as an identity verification tool to limit the number of mints per Discord account or reduce bot activity.
## 3. Support us with a donation
- DexoFriend is a free service, but you may optionally support our project by donating spots on your whitelist.
- This is totally voluntary and will not affect how the bot works, so no pressure!
- Simply use the donate command as described below to donate a specified number of whitelist spots to holders of DexoWorlds. If you have limited whitelisting to a specific role, you may also specify which role on your server should be assigned to the winners.
- You will also have the option to write a personalized message to DexoWorld holders which will be displayed with the giveaway.
- A raffle will be created on the DexoWorlds server, and holders will be notified to enter.
- DexoFriend will generate an invite link to your server, and entrants must join your server before being able to enter the giveaway.
- After 72h, winners will be selected, notified, automatically added to your whitelist, and assigned any specified roles. The winners will then have to manually go to your whitelisting channel and update their address.
## 4. Need help?
- Find us on Twitter, Discord, and GitHub!
- Have questions? Find us on Twitter at [@dexoworlds](https://www.twitter.com/dexoworlds) and [@pastapleas3](https://www.twitter.com/pastapleas3).
- Wanna chat? Join the [DexoWorlds Discord Server](https://discord.gg/beaUBWhXaq). We've got a channel set up just for DexoFriend stuff!
- Found a bug? Feature request? Just wanna check out the code? [Open up an issue on GitHub](https://github.com/astrojarred/dexofriend)!