import glob
import logging
import os

import exifread
from django.conf import settings
from django.core.files.base import ContentFile, File
# from storages.backends.s3boto3 import S3Boto3Storage
# from storages.backends.sftpstorage import SFTPStorage
from django.core.files.storage import FileSystemStorage
from imagekit import ImageSpec
#from imagekit.models import ImageSpecField
from imagekit.processors import ResizeToFill, SmartResize, Transpose
from PIL import Image

logger = logging.getLogger("mail")


# class StaticStorage(S3Boto3Storage):
#     location = settings.AWS_STATIC_LOCATION

# class PublicMediaStorage(S3Boto3Storage):
#     location = settings.AWS_PUBLIC_MEDIA_LOCATION
#     file_overwrite = False

#class PrivateUploadStorage(SFTPStorage):

class Thumbnail(ImageSpec):
    processors = [SmartResize(100, 100)]
    format = 'JPEG'
    options = {'quality': 60}


# class MainImage(ImageSpec):
#     processors=[Transpose(), SmartResize(750, 400)],
#     format = 'JPEG',
#     options={'quality': 75}



class PrivateUploadStorage(FileSystemStorage):

    def _save(self, name, content):
        """Save file via SFTP."""
        super(PrivateUploadStorage, self)._save(name, content)

        dir = os.path.join(settings.MEDIA_ROOT, os.path.dirname(name))
        pathname = os.path.join(settings.MEDIA_ROOT, name)
        # this is not working - error: OSError: cannot identify image file <_io.BufferedRandom name='/Users/pbright/Development/iofh/media/partnerpix/maddog1/IMG_maddog_20180518_154231_aKaqYR1.jpg'>
        # but it is an image....
        #resize_and_make_thumbs(pathname)
        _read_img_and_correct_exif_orientation(pathname)

        return name

# content bytes has not function read
# def _save(self, name, content):
#     """Save file via SFTP.
#     Modified to handle InMemory"""
#
#     path = self._remote_path(name)
#     dirname = self._pathmod.dirname(path)
#     if not self.exists(dirname):
#         self._mkdir(dirname)
#
#     f = self.sftp.open(path, 'wb')
#
#     #TODO: this is a desparate hack to get it working - needs doing properly
#     try:
#         content.open()
#         f.write(content.file.read())
#
#     except:
#         f.write(content.read())
#
#     f.close()
#     # set file permissions if configured
#     if self._file_mode is not None:
#         self.sftp.chmod(path, self._file_mode)
#     if self._uid or self._gid:
#         self._chown(path, uid=self._uid, gid=self._gid)
#     return name


def resize_and_make_thumbs(rootdir):
    '''brute force check directory and resize and make thumb for any file that does not have one
    Assumes that if there is no thumb it has not already been resized'''
    #NOTE assuming all files are .jpg

    for filename in glob.iglob(os.path.join(rootdir ,'**/*.jpg'), recursive=True):
        print(filename)
        # any way of ignore _thumbs?
        if filename[:10] != "_thumb.jpg":

            size = os.path.getsize(filename)
            print(size)
            if size < 1:
                logger.warning("File with no content found: %s" % (filename))
                continue

            print("Processing")
            # does this file have a matching thumb?
            thumb_name = filename[:-4] + "_thumb.jpg"
            if not os.path.isfile(thumb_name):

                with open(filename, 'wb+') as img:
                    # make thumb
                    image_generator = Thumbnail(source=img)
                    result = image_generator.generate()

                    with open(thumb_name, 'wb') as dest:
                        dest.write(result.read())

                    # resize image
                    resized = MainImage(source=img)
                    result = resized.generate()
                    img.seek(0)
                    img.write(result.read())




def _read_img_and_correct_exif_orientation(path):
    #note used - not sure why I seem to be opening the file twice?
    im = Image.open(path)
    save = False
    tags = {}
    with open(path, 'rb') as f:
        tags = exifread.process_file(f, details=False)
    if "Image Orientation" in tags.keys():
        orientation = tags["Image Orientation"]
        logging.debug("Orientation: %s (%s)", orientation, orientation.values)
        val = orientation.values
        if 5 in val:
            val += [4,8]
        if 7 in val:
            val += [4, 6]
        if 3 in val:
            logging.debug("Rotating by 180 degrees.")
            im = im.transpose(Image.ROTATE_180)
            save = True
        if 4 in val:
            logging.debug("Mirroring horizontally.")
            im = im.transpose(Image.FLIP_TOP_BOTTOM)
            save = True
        if 6 in val:
            logging.debug("Rotating by 270 degrees.")
            im = im.transpose(Image.ROTATE_270)
            save = True
        if 8 in val:
            logging.debug("Rotating by 90 degrees.")
            im = im.transpose(Image.ROTATE_90)
            save = True

        if save:
            im.save()

    return im
