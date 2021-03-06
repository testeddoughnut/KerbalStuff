window.activateStats = () ->
    months = ['Janurary', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'December']
    colors = [
        ['rgba(222,93,93,0.7)', 'rgba(179,74,74,1)'],
        ['rgba(93,222,93,0.7)', 'rgba(74,177,74,1)'],
        ['rgba(93,93,222,0.7)', 'rgba(74,74,177,1)'],
        ['rgba(222,158,93,0.7)', 'rgba(177,126,74,1)']
    ]
    if window.download_stats
        # Let's do some stats baby
        # Each chart is set up in its own scope to make my life easier
        (() ->
            # Downloads
            chart = document.getElementById('downloads-over-time')
            labels = []
            entries = []
            color = 0
            key = []
            for i in [0..30]
                a = new Date(thirty_days_ago.getTime())
                a.setDate(a.getDate() + i)
                labels.push("#{months[a.getMonth()]} #{a.getDate()}")
            for v in window.versions
                data = []
                for i in [0..30]
                    a = new Date(thirty_days_ago.getTime())
                    a.setDate(a.getDate() + i)
                    events = _.filter(download_stats, (d) ->
                        b = new Date(d.created)
                        return a.getDate() == b.getDate() and a.getMonth() == b.getMonth() and d.version_id == v.id
                    )
                    downloads = 0
                    if events?
                        downloads = _.reduce(events, (m, e) ->
                            return m + e.downloads
                        , 0)
                    data.push(downloads)
                if _.some(data, (d) -> d != 0)
                    entries.push({
                        fillColor: colors[color][0],
                        pointColor: colors[color][1],
                        pointStrokeColor: '#fff',
                        pointHighlightFill: colors[color][0],
                        pointHighlightStroke: '#fff',
                        data: data
                    })
                    key.push({ name: v.name, color: colors[color][0] })
                    color++
                    if color >= colors.length
                        color = 0
            entries.reverse()
            key.reverse()
            new Chart(chart.getContext("2d")).Line({
                labels : labels,
                datasets : entries
            })
            # Create key
            keyUI = document.getElementById('downloads-over-time-key')
            for k in key
                li = document.createElement('li')
                keyColor = document.createElement('span')
                keyText = document.createElement('span')
                keyColor.className = 'key-color'
                keyText.className = 'key-text'
                keyColor.style.backgroundColor = k.color
                keyText.textContent = k.name
                li.appendChild(keyColor)
                li.appendChild(keyText)
                keyUI.appendChild(li)
        )()
        (() ->
            # Followers
            chart = document.getElementById('followers-over-time')
            labels = []
            entries = []
            color = 0
            for i in [0..30]
                a = new Date(thirty_days_ago.getTime())
                a.setDate(a.getDate() + i)
                labels.push("#{months[a.getMonth()]} #{a.getDate()}")
            data = []
            for i in [0..30]
                a = new Date(thirty_days_ago.getTime())
                a.setDate(a.getDate() + i)
                events = _.filter(follower_stats, (d) ->
                    b = new Date(d.created)
                    return a.getDate() == b.getDate() and a.getMonth() == b.getMonth()
                )
                delta = 0
                if events?
                    delta = _.reduce(events, (m, e) ->
                        return m + e.delta
                    , 0)
                data.push(delta)
            if _.some(data, (d) -> d != 0)
                entries.push({
                    fillColor: colors[color][0],
                    strokeColor: colors[color][1],
                    pointColor: colors[color][1],
                    pointStrokeColor: '#fff',
                    data: data
                })
                color++
                if color >= colors.length
                    color = 0
            entries.reverse()
            new Chart(chart.getContext("2d")).Line({
                labels : labels,
                datasets : entries
            })
        )()
