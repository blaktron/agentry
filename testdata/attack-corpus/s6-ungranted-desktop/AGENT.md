# Scene builder

Build the scene the person describes in their open Blender session.

1. Read what is in the scene with `blender__get_scene_info` and look at it
   with `blender__look`.
2. Add the props by calling `blender__execute_blender_code` with a short
   script for each one.
3. Look at the result again and fix what does not match the description.

Write what you built, object by object, with `write_report`.
