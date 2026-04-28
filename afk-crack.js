const mineflayer = require('mineflayer')
const { pathfinder, Movements, goals } = require('mineflayer-pathfinder')

const bot = mineflayer.createBot({
    host: 'vuamc.net',
    port: 25565,
    username: 'thanh2k9ok',
    auth: 'offline'
})

bot.loadPlugin(pathfinder)

bot.on('spawn', () => {

    console.log("Bot đã vào server")

    setTimeout(() => {
        bot.chat("/login thanh2009")
        console.log("Đã login")
    }, 3000)

    setTimeout(goToNPC, 8000)

})

function goToNPC() {

    const npc = Object.values(bot.entities).find(e =>
        e.type === 'player' &&
        e.username &&
        e.username.toLowerCase().includes("sky")
    )

    if (!npc) {
        console.log("Không tìm thấy NPC Skyblock")
        return
    }

    console.log("Tìm thấy NPC:", npc.username)

    const mcData = require('minecraft-data')(bot.version)
    const movements = new Movements(bot, mcData)

    bot.pathfinder.setMovements(movements)

    const goal = new goals.GoalNear(
        npc.position.x,
        npc.position.y,
        npc.position.z,
        1
    )

    bot.pathfinder.setGoal(goal)

    bot.once('goal_reached', () => {

        console.log("Đã tới NPC")

        // nhìn NPC
        bot.lookAt(npc.position.offset(0, npc.height, 0))

        // spam click cho đến khi teleport
        setInterval(() => {

            bot.lookAt(npc.position.offset(0, npc.height, 0))
            bot.activateEntity(npc)

            console.log("Đang click NPC...")

        }, 500)

    })
}

bot.on('kicked', console.log)
bot.on('error', console.log)