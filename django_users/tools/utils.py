import csv

def get_country_timezones():
    country_timezones = {}
    countries = {}
    timezones = []
    with open("./tools/country_timezones.csv", mode='r') as file:
        reader = csv.DictReader(file)
        for row in reader:
            country = row['Code']
            timezone = row['Timezone']
            timezones.append(timezone)
            if country not in country_timezones:
                country_timezones[country] = []
            country_timezones[country].append(timezone)

            if country not in countries:
                countries[country] = row['Country']

    # sort countries by name
    countries = dict(sorted(countries.items(), key=lambda item: item[1]))

    return country_timezones, countries, timezones

def filename_to_bootstrap_icon(filename):
    # Dictionary mapping file extensions to Bootstrap 5 icon class names
    extension_to_icon = {
        'pdf': 'bi-filetype-pdf',
        'doc': 'bi-filetype-doc',
        'docx': 'bi-filetype-docx',
        # 'xls': 'bi-filetype-xls',
        # 'xlsx': 'bi-filetype-xlsx',
        # 'ppt': 'bi-filetype-ppt',
        # 'pptx': 'bi-filetype-pptx',
        # 'jpg': 'bi-filetype-jpg',
        # 'jpeg': 'bi-filetype-jpg',
        # 'png': 'bi-filetype-png',
        # 'gif': 'bi-filetype-gif',
        # 'svg': 'bi-filetype-svg',
        # 'mp3': 'bi-filetype-mp3',
        # 'mp4': 'bi-filetype-mp4',
        # 'zip': 'bi-filetype-zip',
        # 'rar': 'bi-filetype-zip',
        'txt': 'bi-filetype-txt',
        # 'html': 'bi-filetype-html',
        # 'css': 'bi-filetype-css',
        # 'js': 'bi-filetype-js',
        # 'json': 'bi-filetype-json',
        # 'xml': 'bi-filetype-xml',
        # 'csv': 'bi-filetype-csv',
        # 'php': 'bi-filetype-php',
        # 'py': 'bi-filetype-py',
        # 'c': 'bi-filetype-c',
        # 'cpp': 'bi-filetype-cpp',
        # 'exe': 'bi-filetype-exe',

    }

    # Check if the filename contains an extension
    if '.' in filename:
        # Extract the file extension
        extension = filename.rsplit('.', 1)[1].lower()
    else:
        extension = ''

    # Get the corresponding icon class or use a default icon
    icon_class = extension_to_icon.get(extension, 'bi-file-earmark')

    # Construct the HTML code for the icon
    html_code = f'<i class="bi {icon_class}"></i>'

    return html_code
